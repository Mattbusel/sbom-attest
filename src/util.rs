//! Hashing, time, path and identifier helpers.

use anyhow::{Context, Result};
use sha2::{Digest, Sha256, Sha512};
use std::io::Read;
use std::path::{Component as PathPart, Path, PathBuf};

pub fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 15) as usize] as char);
    }
    s
}

pub fn sha256(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

pub fn sha512(bytes: &[u8]) -> String {
    hex(&Sha512::digest(bytes))
}

/// SHA-256 of a file, streamed.
pub fn sha256_file(path: &Path) -> Result<String> {
    let mut f = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex(&h.finalize()))
}

/// Digest of a set of files: SHA-256 over sorted `"<relpath>\0<sha256>\n"` lines.
/// Order and absolute location do not matter, so two checkouts give the same value.
pub fn tree_digest(files: &[(String, String)]) -> String {
    let mut v: Vec<&(String, String)> = files.iter().collect();
    v.sort();
    let mut h = Sha256::new();
    for (p, d) in v {
        h.update(p.as_bytes());
        h.update([0]);
        h.update(d.as_bytes());
        h.update(b"\n");
    }
    hex(&h.finalize())
}

/// RFC 3339 UTC timestamp for a Unix time.
pub fn rfc3339(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m,
        d,
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

// Howard Hinnant's days-to-civil algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// The SBOM timestamp: an explicit value, else SOURCE_DATE_EPOCH, else now.
pub fn timestamp(explicit: Option<i64>) -> String {
    let secs = explicit
        .or_else(|| {
            std::env::var("SOURCE_DATE_EPOCH")
                .ok()
                .and_then(|v| v.trim().parse().ok())
        })
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0)
        });
    rfc3339(secs)
}

/// A name-based UUID (version 8 layout) from a SHA-256 of `seed`, so that the same
/// inventory always gets the same serial number.
pub fn uuid_from(seed: &[u8]) -> String {
    let d = Sha256::digest(seed);
    let mut b = [0u8; 16];
    b.copy_from_slice(&d[..16]);
    b[6] = (b[6] & 0x0f) | 0x80;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex(&b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// Lexically normalise a path (resolve `.` and `..` without touching the disk).
pub fn normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for part in p.components() {
        match part {
            PathPart::CurDir => {}
            PathPart::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Forward-slash string form of a path.
pub fn slash(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

/// How a path is written into an SBOM: relative to the project root when inside it,
/// with the home directory replaced by `~` otherwise (no user names in evidence).
pub fn display_path(p: &Path, root: &Path) -> String {
    let p = normalize(p);
    if let Ok(rel) = p.strip_prefix(root) {
        let s = slash(rel);
        return if s.is_empty() { ".".into() } else { s };
    }
    let s = slash(&p);
    for var in ["HOME", "USERPROFILE"] {
        if let Ok(home) = std::env::var(var) {
            let home = slash(Path::new(&home));
            if !home.is_empty() && s.starts_with(&home) {
                return format!("~{}", &s[home.len()..]);
            }
        }
    }
    s
}

/// Percent-encode a purl name or version segment.
pub fn purl_escape(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || "-._~".contains(c) {
            out.push(c);
        } else {
            let mut buf = [0u8; 4];
            for b in c.encode_utf8(&mut buf).bytes() {
                out.push_str(&format!("%{b:02X}"));
            }
        }
    }
    out
}

/// Characters allowed in an SPDX id or bom-ref suffix.
pub fn id_safe(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

/// Normalise a Cargo-style license string to an SPDX expression
/// ("MIT/Apache-2.0" was the old Cargo spelling of "MIT OR Apache-2.0").
pub fn spdx_expression(raw: &str) -> String {
    let s = raw.trim();
    let s = if s.contains('/') && !s.contains(" OR ") && !s.contains(" AND ") {
        s.split('/').map(str::trim).collect::<Vec<_>>().join(" OR ")
    } else {
        s.to_string()
    };
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// SPDX license ids sbom-attest will pass through to SPDX `licenseDeclared` unchanged.
/// Anything else becomes NOASSERTION there (CycloneDX keeps the declared text).
const KNOWN_LICENSES: &[&str] = &[
    "0BSD",
    "AFL-3.0",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
    "Apache-1.1",
    "Apache-2.0",
    "Artistic-2.0",
    "BSD-1-Clause",
    "BSD-2-Clause",
    "BSD-2-Clause-Patent",
    "BSD-3-Clause",
    "BSD-3-Clause-Clear",
    "BSD-4-Clause",
    "BSL-1.0",
    "CC-BY-4.0",
    "CC0-1.0",
    "CDDL-1.0",
    "CDLA-Permissive-1.0",
    "CDLA-Permissive-2.0",
    "EPL-1.0",
    "EPL-2.0",
    "EUPL-1.2",
    "GPL-2.0-only",
    "GPL-2.0-or-later",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "ISC",
    "LGPL-2.0-only",
    "LGPL-2.0-or-later",
    "LGPL-2.1-only",
    "LGPL-2.1-or-later",
    "LGPL-3.0-only",
    "LGPL-3.0-or-later",
    "MIT",
    "MIT-0",
    "MPL-1.1",
    "MPL-2.0",
    "MS-PL",
    "NCSA",
    "OFL-1.1",
    "OpenSSL",
    "PostgreSQL",
    "Python-2.0",
    "Ruby",
    "Unicode-3.0",
    "Unicode-DFS-2016",
    "Unlicense",
    "UPL-1.0",
    "W3C",
    "WTFPL",
    "X11",
    "Zlib",
    "zlib-acknowledgement",
    "curl",
    "bzip2-1.0.6",
    "blessing",
    "GPL-2.0",
    "GPL-3.0",
    "LGPL-2.1",
    "LGPL-3.0",
    "AGPL-3.0",
    "GPL-2.0+",
    "GPL-3.0+",
    "LGPL-2.1+",
    "LGPL-3.0+",
];
const KNOWN_EXCEPTIONS: &[&str] = &[
    "LLVM-exception",
    "Classpath-exception-2.0",
    "GCC-exception-3.1",
    "Autoconf-exception-3.0",
    "Bison-exception-2.2",
    "Linux-syscall-note",
];

/// True if every license id in the expression is a known SPDX id.
pub fn spdx_expression_known(expr: &str) -> bool {
    let mut expect_exception = false;
    let mut any = false;
    for tok in expr.replace(['(', ')'], " ").split_whitespace() {
        match tok {
            "AND" | "OR" => {}
            "WITH" => expect_exception = true,
            t if expect_exception => {
                if !KNOWN_EXCEPTIONS.contains(&t) {
                    return false;
                }
                expect_exception = false;
            }
            t => {
                let t = t.trim_end_matches('+');
                if !KNOWN_LICENSES.contains(&t) && !KNOWN_LICENSES.contains(&tok) {
                    return false;
                }
                any = true;
            }
        }
    }
    any && !expect_exception
}

/// RFC 8785 (JCS) canonical form. serde_json's default map is sorted by key and its
/// string escaping matches JCS for the integer-only documents written here.
pub fn canonical(v: &serde_json::Value) -> Vec<u8> {
    use serde_json::Value;
    fn sort(v: &Value) -> Value {
        match v {
            Value::Object(m) => {
                let mut keys: Vec<&String> = m.keys().collect();
                // JCS orders by UTF-16 code units; identical to byte order for ASCII keys
                keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
                let mut out = serde_json::Map::new();
                for k in keys {
                    out.insert(k.clone(), sort(&m[k]));
                }
                Value::Object(out)
            }
            Value::Array(a) => Value::Array(a.iter().map(sort).collect()),
            // JCS writes numbers the way ECMAScript does: 1.0 is "1"
            Value::Number(n) if n.is_f64() => match n.as_f64() {
                Some(f) if f.fract() == 0.0 && f.abs() < 9_007_199_254_740_992.0 => {
                    Value::from(f as i64)
                }
                _ => v.clone(),
            },
            other => other.clone(),
        }
    }
    serde_json::to_vec(&sort(v)).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_known_points() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn uuid_is_stable_and_versioned() {
        let a = uuid_from(b"x");
        assert_eq!(a, uuid_from(b"x"));
        assert_ne!(a, uuid_from(b"y"));
        assert_eq!(&a[14..15], "8");
        assert!(matches!(&a[19..20], "8" | "9" | "a" | "b"));
    }

    #[test]
    fn licenses_normalise() {
        assert_eq!(spdx_expression("MIT/Apache-2.0"), "MIT OR Apache-2.0");
        assert_eq!(spdx_expression("MIT  OR  Apache-2.0"), "MIT OR Apache-2.0");
        assert!(spdx_expression_known("(MIT OR Apache-2.0) AND Unicode-3.0"));
        assert!(spdx_expression_known("Apache-2.0 WITH LLVM-exception"));
        // webpki-roots 1.x ships under the Mozilla root data license
        assert!(spdx_expression_known("CDLA-Permissive-2.0"));
        assert!(spdx_expression_known("blessing"));
        assert!(!spdx_expression_known("Custom-License"));
        assert!(!spdx_expression_known(""));
    }

    #[test]
    fn tree_digest_ignores_order() {
        let a = vec![("a.c".into(), "1".into()), ("b.c".into(), "2".into())];
        let b = vec![("b.c".into(), "2".into()), ("a.c".into(), "1".into())];
        assert_eq!(tree_digest(&a), tree_digest(&b));
    }

    #[test]
    fn normalize_dots() {
        assert_eq!(slash(&normalize(Path::new("/a/b/../c/./d"))), "/a/c/d");
    }
}
