//! Post-build analysis of the shipped artifact: ELF, PE, Mach-O and static archives.
//!
//! Reads the dependency list cargo-auditable embeds (`.dep-v0`), the shared libraries
//! the loader will pull in (DT_NEEDED / PE imports / Mach-O load commands), the
//! compiler identification strings in `.comment`, the GNU build id, and the members of
//! static archives.

use crate::model::{Component, Inventory, Kind, Lang, Phase, Scope};
use crate::util::{purl_escape, sha256, sha512};
use anyhow::{bail, Context, Result};
use goblin::Object;
use serde_json::Value;
use std::path::Path;

#[derive(Clone, Debug, Default)]
pub struct AuditablePkg {
    pub name: String,
    pub version: String,
    pub source: String,
    pub build_only: bool,
    pub root: bool,
    pub deps: Vec<usize>,
}

#[derive(Clone, Debug, Default)]
pub struct BinaryInfo {
    pub format: String,
    pub arch: String,
    pub sha256: String,
    pub sha512: String,
    pub needed: Vec<String>,
    pub compilers: Vec<String>,
    pub build_id: Option<String>,
    pub auditable: Option<Vec<AuditablePkg>>,
    pub members: Vec<String>,
    pub interpreter: Option<String>,
    /// DT_RUNPATH / DT_RPATH entries
    pub runpaths: Vec<String>,
}

fn elf_machine(m: u16) -> &'static str {
    use goblin::elf::header::*;
    match m {
        EM_X86_64 => "x86_64",
        EM_386 => "x86",
        EM_ARM => "arm",
        EM_AARCH64 => "aarch64",
        EM_RISCV => "riscv",
        EM_MIPS => "mips",
        EM_PPC => "powerpc",
        EM_PPC64 => "powerpc64",
        EM_XTENSA => "xtensa",
        _ => "unknown",
    }
}

/// Decode a cargo-auditable `.dep-v0` payload (zlib-compressed JSON).
pub fn decode_auditable(compressed: &[u8]) -> Result<Vec<AuditablePkg>> {
    let raw = miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(compressed, 64 << 20)
        .map_err(|e| anyhow::anyhow!("inflating .dep-v0: {e:?}"))?;
    let v: Value = serde_json::from_slice(&raw).context("parsing .dep-v0 JSON")?;
    let mut out = Vec::new();
    for p in v["packages"].as_array().into_iter().flatten() {
        out.push(AuditablePkg {
            name: p["name"].as_str().unwrap_or_default().to_string(),
            version: p["version"].as_str().unwrap_or_default().to_string(),
            source: p["source"].as_str().unwrap_or("crates.io").to_string(),
            build_only: p["kind"].as_str() == Some("build"),
            root: p["root"].as_bool().unwrap_or(false),
            deps: p["dependencies"]
                .as_array()
                .map(|d| {
                    d.iter()
                        .filter_map(|x| x.as_u64())
                        .map(|x| x as usize)
                        .collect()
                })
                .unwrap_or_default(),
        });
    }
    Ok(out)
}

fn comment_strings(data: &[u8]) -> Vec<String> {
    data.split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

pub fn analyze(path: &Path) -> Result<BinaryInfo> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    analyze_bytes(&bytes)
}

pub fn analyze_bytes(bytes: &[u8]) -> Result<BinaryInfo> {
    let mut info = BinaryInfo {
        sha256: sha256(bytes),
        sha512: sha512(bytes),
        ..Default::default()
    };
    match Object::parse(bytes)? {
        Object::Elf(elf) => {
            info.format = if elf.is_64 { "elf64" } else { "elf32" }.into();
            info.arch = elf_machine(elf.header.e_machine).into();
            info.needed = elf.libraries.iter().map(|s| s.to_string()).collect();
            info.interpreter = elf.interpreter.map(String::from);
            info.runpaths = elf
                .runpaths
                .iter()
                .chain(elf.rpaths.iter())
                .flat_map(|r| r.split(':'))
                .filter(|r| !r.is_empty())
                .map(String::from)
                .collect();
            for sh in &elf.section_headers {
                let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
                if sh.sh_type == goblin::elf::section_header::SHT_NOBITS {
                    continue;
                }
                let start = sh.sh_offset as usize;
                let end = start.saturating_add(sh.sh_size as usize);
                let Some(data) = bytes.get(start..end) else {
                    continue;
                };
                match name {
                    ".comment" => info.compilers.extend(comment_strings(data)),
                    ".dep-v0" => info.auditable = Some(decode_auditable(data)?),
                    ".note.gnu.build-id" if data.len() > 16 => {
                        // Elf note: namesz, descsz, type, "GNU\0", desc
                        let namesz = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
                        let descsz = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;
                        let off = 12 + namesz.div_ceil(4) * 4;
                        if let Some(id) = data.get(off..off + descsz) {
                            info.build_id = Some(crate::util::hex(id));
                        }
                    }
                    _ => {}
                }
            }
        }
        Object::PE(pe) => {
            info.format = if pe.is_64 { "pe64" } else { "pe32" }.into();
            info.arch = match pe.header.coff_header.machine {
                0x8664 => "x86_64",
                0x14c => "x86",
                0xaa64 => "aarch64",
                0x1c0 | 0x1c4 => "arm",
                _ => "unknown",
            }
            .into();
            info.needed = pe.libraries.iter().map(|s| s.to_string()).collect();
            for s in &pe.sections {
                if s.name().ok() == Some(".dep-v0") {
                    let start = s.pointer_to_raw_data as usize;
                    let end = start + s.size_of_raw_data as usize;
                    if let Some(data) = bytes.get(start..end) {
                        // raw section data is padded to the file alignment; zlib stops at its end
                        let len = (s.virtual_size as usize).min(data.len()).max(1);
                        info.auditable = Some(decode_auditable(&data[..len])?);
                    }
                }
            }
        }
        Object::Mach(goblin::mach::Mach::Binary(m)) => {
            info.format = "mach-o".into();
            info.arch = match m.header.cputype {
                goblin::mach::cputype::CPU_TYPE_X86_64 => "x86_64",
                goblin::mach::cputype::CPU_TYPE_ARM64 => "aarch64",
                _ => "unknown",
            }
            .into();
            info.needed = m
                .libs
                .iter()
                .filter(|l| **l != "self")
                .map(|s| s.to_string())
                .collect();
            for seg in &m.segments {
                for (sect, data) in seg.sections().unwrap_or_default() {
                    if sect.name().ok() == Some(".dep-v0") {
                        info.auditable = Some(decode_auditable(data)?);
                    }
                }
            }
        }
        Object::Mach(_) => {
            info.format = "mach-o-fat".into();
        }
        Object::Archive(ar) => {
            info.format = "ar".into();
            info.members = ar.members().iter().map(|s| s.to_string()).collect();
            info.members.sort();
        }
        _ => bail!("unrecognised binary format"),
    }
    Ok(info)
}

/// Record the analysed artifact: it becomes the hash of the root component, its
/// embedded cargo dependency list becomes components, and each shared library it
/// loads becomes a component to be resolved on disk.
pub fn apply(inv: &mut Inventory, path: &Path, info: &BinaryInfo) {
    inv.phases.insert(Phase::PostBuild);
    let root = &mut inv.root;
    root.hashes
        .retain(|(a, _)| a != "SHA-256" && a != "SHA-512");
    root.hashes.push(("SHA-256".into(), info.sha256.clone()));
    root.hashes.push(("SHA-512".into(), info.sha512.clone()));
    root.hash_subject = Some("binary".into());
    root.evidence.insert("binary".into());
    root.properties.insert(
        "sbom-attest:artifact".into(),
        path.file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_default(),
    );
    root.properties
        .insert("sbom-attest:binary:format".into(), info.format.clone());
    root.properties
        .insert("sbom-attest:binary:arch".into(), info.arch.clone());
    if let Some(id) = &info.build_id {
        root.properties
            .insert("sbom-attest:binary:gnu-build-id".into(), id.clone());
    }
    if info.format.starts_with("elf") && info.interpreter.is_none() && info.needed.is_empty() {
        root.properties
            .insert("sbom-attest:binary:linkage".into(), "static".into());
    }
    if !info.compilers.is_empty() {
        let mut c = info.compilers.clone();
        c.sort();
        c.dedup();
        inv.properties
            .insert("sbom-attest:compiler-ident".into(), c.join(" | "));
    }
    let root_id = inv.root.id.clone();

    if let Some(pkgs) = &info.auditable {
        apply_auditable(inv, pkgs);
    }

    for lib in &info.needed {
        let mut c = Component::new(format!("dynlib:{lib}"), Kind::Library, lib);
        c.evidence.insert("binary:needed".into());
        c.properties
            .insert("sbom-attest:linkage".into(), "dynamic".into());
        c.lang = Lang::C;
        inv.add(c);
        inv.depend(&root_id, &format!("dynlib:{lib}"));
    }
}

/// Merge the binary's cargo-auditable dependency list into the inventory.
///
/// When the Rust side already ran (`cargo tree` for the same package and target),
/// that resolution is the reference: cargo-auditable records the dependency graph
/// from `cargo metadata`, which unifies features across the whole workspace and can
/// list crates that are never compiled into the artifact (test helpers, optional
/// backends). Matching packages get the `cargo-auditable` evidence; packages only
/// cargo-auditable lists are not added as components but are reported in the
/// `sbom-attest:auditable-only` property, so the cross-check stays visible without
/// putting crates in the SBOM that the binary does not contain. Without a cargo
/// scan, the embedded list is the only source and is used as is.
fn apply_auditable(inv: &mut Inventory, pkgs: &[AuditablePkg]) {
    let root_id = inv.root.id.clone();
    let cargo_scanned = inv
        .components
        .values()
        .any(|c| c.evidence.contains("cargo-tree"));
    let ids: Vec<String> = pkgs
        .iter()
        .map(|p| {
            if p.root {
                return root_id.clone();
            }
            match p.source.as_str() {
                "crates.io" | "local" => format!("pkg:cargo/{}@{}", p.name, p.version),
                "git" => {
                    // cargo_src ids git packages as `cargo:<name>@<version>+git.<rev>`;
                    // the embedded data has no revision, so match on the prefix.
                    let prefix = format!("cargo:{}@{}+git", p.name, p.version);
                    inv.components
                        .keys()
                        .find(|k| k.starts_with(&prefix))
                        .cloned()
                        .unwrap_or(prefix)
                }
                _ => format!("cargo:{}@{}+local", p.name, p.version),
            }
        })
        .collect();

    if cargo_scanned {
        let mut only = Vec::new();
        for (p, id) in pkgs.iter().zip(&ids) {
            if p.root {
                inv.root.evidence.insert("cargo-auditable".into());
            } else if let Some(c) = inv.components.get_mut(id) {
                c.evidence.insert("cargo-auditable".into());
            } else {
                only.push(format!("{}@{}", p.name, p.version));
            }
        }
        if !only.is_empty() {
            only.sort();
            only.dedup();
            inv.properties
                .insert("sbom-attest:auditable-only".into(), only.join(", "));
        }
        return;
    }

    for (i, p) in pkgs.iter().enumerate() {
        let id = ids[i].clone();
        let mut c = Component::new(id.clone(), Kind::Library, &p.name);
        c.version = Some(p.version.clone());
        c.lang = Lang::Rust;
        c.purl = Some(format!(
            "pkg:cargo/{}@{}",
            purl_escape(&p.name),
            purl_escape(&p.version)
        ));
        c.scope = if p.build_only {
            Scope::Excluded
        } else {
            Scope::Required
        };
        c.evidence.insert("cargo-auditable".into());
        if p.root {
            inv.root.evidence.insert("cargo-auditable".into());
        } else {
            inv.add(c);
        }
        for d in &p.deps {
            if let Some(to) = ids.get(*d) {
                inv.depend(&id, to);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_auditable_payload() {
        let json = br#"{"packages":[{"name":"app","version":"0.1.0","source":"local","dependencies":[1],"root":true},{"name":"serde","version":"1.0.0","source":"crates.io"},{"name":"cc","version":"1.0.0","source":"crates.io","kind":"build"}]}"#;
        let z = miniz_oxide::deflate::compress_to_vec_zlib(json, 6);
        let pkgs = decode_auditable(&z).unwrap();
        assert_eq!(pkgs.len(), 3);
        assert!(pkgs[0].root);
        assert_eq!(pkgs[0].deps, vec![1]);
        assert!(pkgs[2].build_only);
    }

    #[test]
    fn analyses_own_test_binary() {
        // the running test executable is a real ELF/PE/Mach-O file
        let exe = std::env::current_exe().unwrap();
        let info = analyze(&exe).unwrap();
        assert!(!info.format.is_empty());
        assert_eq!(info.sha256.len(), 64);
    }

    fn pkg(name: &str, source: &str, root: bool, deps: Vec<usize>) -> AuditablePkg {
        AuditablePkg {
            name: name.into(),
            version: "1.0.0".into(),
            source: source.into(),
            build_only: false,
            root,
            deps,
        }
    }

    #[test]
    fn auditable_cross_checks_cargo_scan() {
        let mut inv = Inventory::new(
            Component::new("pkg:cargo/app@1.0.0", Kind::Application, "app"),
            "2026-01-01T00:00:00Z".into(),
        );
        for id in ["pkg:cargo/serde@1.0.0", "cargo:kube@1.0.0+git.0123456789ab"] {
            let mut c = Component::new(id, Kind::Library, "x");
            c.evidence.insert("cargo-tree".into());
            inv.add(c);
        }
        let pkgs = vec![
            pkg("app", "local", true, vec![1, 2, 3]),
            pkg("serde", "crates.io", false, vec![]),
            pkg("kube", "git", false, vec![]),
            pkg("proptest", "crates.io", false, vec![]),
        ];
        apply_auditable(&mut inv, &pkgs);
        // no new components: the git package matched its cargo id, proptest is reported
        assert_eq!(inv.components.len(), 2);
        assert!(inv.components["cargo:kube@1.0.0+git.0123456789ab"]
            .evidence
            .contains("cargo-auditable"));
        assert!(inv.components["pkg:cargo/serde@1.0.0"]
            .evidence
            .contains("cargo-auditable"));
        assert!(inv.root.evidence.contains("cargo-auditable"));
        assert_eq!(
            inv.properties
                .get("sbom-attest:auditable-only")
                .map(String::as_str),
            Some("proptest@1.0.0")
        );
    }

    #[test]
    fn auditable_alone_lists_everything() {
        let mut inv = Inventory::new(
            Component::new("src:app", Kind::Application, "app"),
            "2026-01-01T00:00:00Z".into(),
        );
        let pkgs = vec![
            pkg("app", "local", true, vec![1]),
            pkg("serde", "crates.io", false, vec![]),
        ];
        apply_auditable(&mut inv, &pkgs);
        assert!(inv.components.contains_key("pkg:cargo/serde@1.0.0"));
        assert!(inv.deps["src:app"].contains("pkg:cargo/serde@1.0.0"));
        assert!(!inv.properties.contains_key("sbom-attest:auditable-only"));
    }

    #[test]
    fn comment_split() {
        assert_eq!(
            comment_strings(b"GCC: (Ubuntu) 13.2.0\0rustc version 1.80\0\0"),
            vec!["GCC: (Ubuntu) 13.2.0", "rustc version 1.80"]
        );
    }
}
