//! `audit`: verify a published SBOM against what the build actually links.
//!
//! A published SBOM is a claim. This module checks the claim against the evidence a
//! build leaves behind: `Cargo.lock`, the crate graph `cargo tree` resolves, the
//! dependency list cargo-auditable embeds in a binary, the C/C++ sources a
//! `-sys`/`-src` crate compiles in, vendored C/C++ directories in the source tree, and
//! `compile_commands.json`. Every disagreement is a finding, and every finding fails
//! the audit unless its class is explicitly waived.
//!
//! The checks are pure functions over a [`Truth`] and a [`Doc`], so they can be
//! tested and reused without running cargo. [`cargo_graph`], [`parse_lock`],
//! [`scan_vendored`] and [`fetch_index`] collect the evidence.

use crate::read::{Doc, DocComponent};
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::process::Command;

/// The kinds of disagreement between an SBOM and the build.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Class {
    /// Linked into the shipped artifact, missing from the SBOM.
    Omitted,
    /// Compiled or run during the build (proc macro, build script), missing from the SBOM.
    OmittedBuild,
    /// The build compiles C/C++ source the SBOM never names.
    VendoredC,
    /// The SBOM names the component at a different version than the build uses.
    VersionDrift,
    /// The SBOM's hash disagrees with Cargo.lock or the registry.
    HashDrift,
    /// The SBOM declares something the build does not contain.
    Phantom,
    /// No exact version: missing, a range, or a placeholder.
    Unpinned,
    /// No hash, although the build pins one.
    Unhashed,
    /// The build uses a version its registry has yanked.
    Yanked,
    /// No license on the component.
    NoLicense,
}

impl Class {
    pub const ALL: [Class; 10] = [
        Class::Omitted,
        Class::OmittedBuild,
        Class::VendoredC,
        Class::VersionDrift,
        Class::HashDrift,
        Class::Phantom,
        Class::Unpinned,
        Class::Unhashed,
        Class::Yanked,
        Class::NoLicense,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Class::Omitted => "omitted",
            Class::OmittedBuild => "omitted-build",
            Class::VendoredC => "vendored-c",
            Class::VersionDrift => "version-drift",
            Class::HashDrift => "hash-drift",
            Class::Phantom => "phantom",
            Class::Unpinned => "unpinned",
            Class::Unhashed => "unhashed",
            Class::Yanked => "yanked",
            Class::NoLicense => "no-license",
        }
    }

    /// What a finding of this class means, in one line.
    pub fn meaning(self) -> &'static str {
        match self {
            Class::Omitted => "linked into the artifact, missing from the SBOM",
            Class::OmittedBuild => {
                "runs or generates code during the build (proc macro, build script), missing from the SBOM"
            }
            Class::VendoredC => {
                "C/C++ source compiled into the build that the SBOM never names, so CVE scanners never match it"
            }
            Class::VersionDrift => "the SBOM names a different version than the build uses",
            Class::HashDrift => "the SBOM's hash does not match Cargo.lock or the registry",
            Class::Phantom => "declared in the SBOM, not in the build",
            Class::Unpinned => "no exact version (missing, a range or a placeholder)",
            Class::Unhashed => "no hash in the SBOM although the build pins one",
            Class::Yanked => "the build uses a version the registry has yanked",
            Class::NoLicense => "no license in the SBOM",
        }
    }

    /// What waiving this class gives up, printed loudly when it is waived.
    pub fn waiver_cost(self) -> &'static str {
        match self {
            Class::Omitted => "this run does NOT check that the SBOM lists every crate the build links",
            Class::OmittedBuild => "this run does NOT check build-time code (proc macros, build scripts), where supply-chain attacks run",
            Class::VendoredC => "this run does NOT check for C/C++ compiled in under a Rust crate's name",
            Class::VersionDrift => "this run accepts an SBOM whose versions are not the ones built",
            Class::HashDrift => "this run accepts hashes that do not match what was downloaded",
            Class::Phantom => "this run accepts components the build does not contain",
            Class::Unpinned => "this run accepts components without an exact version",
            Class::Unhashed => "this run accepts components without a hash",
            Class::Yanked => "this run does NOT fail on yanked crates",
            Class::NoLicense => "this run accepts components without a license",
        }
    }

    pub fn parse(s: &str) -> Result<Class> {
        let s = s.trim().to_ascii_lowercase().replace('_', "-");
        Class::ALL
            .into_iter()
            .find(|c| c.as_str() == s)
            .ok_or_else(|| {
                anyhow!(
                    "unknown check `{s}`; one of: {}",
                    Class::ALL.map(|c| c.as_str()).join(", ")
                )
            })
    }
}

/// One disagreement between the SBOM and the build.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub class: Class,
    pub name: String,
    pub version: Option<String>,
    pub detail: String,
    /// Which input proves it ("Cargo.lock", "cargo tree", "source tree", ...).
    pub evidence: String,
}

/// Where a crate comes from.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Origin {
    CratesIo,
    /// Another registry, by name or URL.
    Registry(String),
    /// A git repository; the commit when known.
    Git(String),
    /// A path on disk (workspace members, path dependencies).
    Path,
}

impl Origin {
    /// From a Cargo.lock `source` value (None means a path package).
    pub fn from_lock(source: Option<&str>) -> Origin {
        match source {
            None => Origin::Path,
            Some(s) if s.contains("crates.io-index") || s.contains("index.crates.io") => {
                Origin::CratesIo
            }
            Some(s) if s.starts_with("git+") => Origin::Git(s.to_string()),
            Some(s) => Origin::Registry(s.to_string()),
        }
    }

    /// From the parenthesised source `cargo tree` prints (None means crates.io).
    pub fn from_tree(source: Option<&str>) -> Origin {
        match source {
            None => Origin::CratesIo,
            Some(s) if s.starts_with("registry") => Origin::Registry(s.to_string()),
            Some(s) if s.contains("://") => Origin::Git(s.to_string()),
            Some(_) => Origin::Path,
        }
    }
}

/// One `[[package]]` of a Cargo.lock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockPackage {
    pub name: String,
    pub version: String,
    pub source: Option<String>,
    pub checksum: Option<String>,
}

impl LockPackage {
    pub fn origin(&self) -> Origin {
        Origin::from_lock(self.source.as_deref())
    }
}

/// Parse a Cargo.lock (format 1 to 4). Format-1 checksums from the `[metadata]` table
/// are attached to their packages.
pub fn parse_lock(text: &str) -> Vec<LockPackage> {
    let mut out: Vec<LockPackage> = Vec::new();
    let mut cur: Option<LockPackage> = None;
    let mut in_metadata = false;
    let mut legacy: HashMap<(String, String), String> = HashMap::new();
    let value = |l: &str| {
        l.split_once('=')
            .map(|(_, v)| v.trim().trim_matches('"').to_string())
    };
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            if let Some(p) = cur.take() {
                out.push(p);
            }
            in_metadata = line == "[metadata]";
            if line == "[[package]]" {
                cur = Some(LockPackage {
                    name: String::new(),
                    version: String::new(),
                    source: None,
                    checksum: None,
                });
            }
            continue;
        }
        if in_metadata {
            // "checksum name version (source)" = "sha"
            if let Some(rest) = line.strip_prefix("\"checksum ") {
                if let Some((key, sum)) = rest.split_once("\" = \"") {
                    let mut it = key.split(' ');
                    if let (Some(n), Some(v)) = (it.next(), it.next()) {
                        legacy.insert(
                            (n.to_string(), v.to_string()),
                            sum.trim_end_matches('"').to_string(),
                        );
                    }
                }
            }
            continue;
        }
        let Some(p) = cur.as_mut() else { continue };
        let key = line.split(['=', ' ']).next().unwrap_or("");
        match key {
            "name" => p.name = value(line).unwrap_or_default(),
            "version" => p.version = value(line).unwrap_or_default(),
            "source" => p.source = value(line),
            "checksum" => p.checksum = value(line),
            _ => {}
        }
    }
    if let Some(p) = cur.take() {
        out.push(p);
    }
    out.retain(|p| !p.name.is_empty() && !p.version.is_empty());
    for p in &mut out {
        if p.checksum.is_none() {
            p.checksum = legacy.remove(&(p.name.clone(), p.version.clone()));
        }
    }
    out
}

/// One crate of the resolved build graph.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GraphCrate {
    pub name: String,
    pub version: String,
    pub origin: Origin,
    /// Only used to build (proc macro, build dependency), not linked into the artifact.
    pub build_only: bool,
    pub features: Vec<String>,
}

/// What `cargo tree` should resolve.
#[derive(Clone, Debug, Default)]
pub struct GraphOptions {
    pub manifest_path: PathBuf,
    /// Workspace packages to resolve; empty means the whole workspace.
    pub package: Vec<String>,
    /// A triple, `all` (every platform, what cargo-cyclonedx records by default) or
    /// None for the host.
    pub target: Option<String>,
    pub features: Vec<String>,
    pub all_features: bool,
    pub no_default_features: bool,
    pub offline: bool,
    pub locked: bool,
}

fn cargo_cmd() -> Command {
    Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
}

fn run_tree(o: &GraphOptions, edges: &str) -> Result<String> {
    let mut cmd = cargo_cmd();
    cmd.args([
        "tree",
        "--prefix",
        "depth",
        "--charset",
        "ascii",
        "-f",
        "{p}|{f}",
        "-e",
        edges,
    ]);
    cmd.arg("--manifest-path").arg(&o.manifest_path);
    if o.package.is_empty() {
        cmd.arg("--workspace");
    }
    for p in &o.package {
        cmd.arg("--package").arg(p);
    }
    if let Some(t) = &o.target {
        cmd.arg("--target").arg(t);
    }
    if !o.features.is_empty() {
        cmd.arg("--features").arg(o.features.join(","));
    }
    if o.all_features {
        cmd.arg("--all-features");
    }
    if o.no_default_features {
        cmd.arg("--no-default-features");
    }
    if o.offline {
        cmd.arg("--offline");
    }
    if o.locked {
        cmd.arg("--locked");
    }
    let out = cmd.output().with_context(|| format!("running {cmd:?}"))?;
    if !out.status.success() {
        bail!(
            "{cmd:?} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Turn two `cargo tree` listings (normal edges, normal+build edges) into the graph.
pub fn graph_from_trees(normal: &str, full: &str) -> Vec<GraphCrate> {
    let proc_macros: BTreeSet<(String, String)> = full
        .lines()
        .filter(|l| l.contains("(proc-macro)"))
        .flat_map(|l| crate::cargo_src::parse_tree(l).into_iter())
        .map(|n| (n.name, n.version))
        .collect();
    let runtime: BTreeSet<(String, String)> = crate::cargo_src::parse_tree(normal)
        .into_iter()
        .map(|n| (n.name, n.version))
        .filter(|k| !proc_macros.contains(k))
        .collect();
    let mut seen: BTreeMap<(String, String), GraphCrate> = BTreeMap::new();
    for n in crate::cargo_src::parse_tree(full) {
        let key = (n.name.clone(), n.version.clone());
        let e = seen.entry(key.clone()).or_insert_with(|| GraphCrate {
            name: n.name.clone(),
            version: n.version.clone(),
            origin: Origin::from_tree(n.source.as_deref()),
            build_only: !runtime.contains(&key),
            features: Vec::new(),
        });
        for f in n.features {
            if !e.features.contains(&f) {
                e.features.push(f);
            }
        }
    }
    seen.into_values().collect()
}

/// Resolve the crate graph the build compiles, with `cargo tree`.
pub fn cargo_graph(o: &GraphOptions) -> Result<Vec<GraphCrate>> {
    let normal = run_tree(o, "normal")?;
    let full = run_tree(o, "normal,build")?;
    Ok(graph_from_trees(&normal, &full))
}

/// C/C++ source that the build compiles in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vendored {
    /// The library, as a scanner would look for it ("openssl", "zstd", "abseil-cpp").
    pub name: String,
    pub version: Option<String>,
    /// "crate openssl-src 300.3.1+3.3.1" or "third_party/zlib (214 C/C++ files)".
    pub evidence: String,
    /// Other names the library is published under.
    pub aliases: Vec<String>,
}

/// `-sys`/`-src` crates whose C library goes by another name.
const SYS_LIBRARIES: &[(&str, &str)] = &[
    ("openssl-src", "openssl"),
    ("libz-sys", "zlib"),
    ("libz-ng-sys", "zlib-ng"),
    ("zstd-sys", "zstd"),
    ("lz4-sys", "lz4"),
    ("bzip2-sys", "bzip2"),
    ("lzma-sys", "xz"),
    ("liblzma-sys", "xz"),
    ("libsqlite3-sys", "sqlite"),
    ("sqlite3-src", "sqlite"),
    ("tikv-jemalloc-sys", "jemalloc"),
    ("jemalloc-sys", "jemalloc"),
    ("libmimalloc-sys", "mimalloc"),
    ("librocksdb-sys", "rocksdb"),
    ("curl-sys", "curl"),
    ("libgit2-sys", "libgit2"),
    ("libssh2-sys", "libssh2"),
    ("libnghttp2-sys", "nghttp2"),
    ("aws-lc-sys", "aws-lc"),
    ("aws-lc-fips-sys", "aws-lc"),
    ("boring-sys", "boringssl"),
    ("protobuf-src", "protobuf"),
    ("onig_sys", "oniguruma"),
    ("snappy-sys", "snappy"),
    ("lmdb-master-sys", "lmdb"),
    ("lmdb-sys", "lmdb"),
    ("hdf5-src", "hdf5"),
    ("netcdf-src", "netcdf-c"),
    ("libdeflate-sys", "libdeflate"),
    ("brotli-sys", "brotli"),
    ("libwebp-sys", "libwebp"),
    ("mozjpeg-sys", "mozjpeg"),
    ("freetype-sys", "freetype"),
    ("harfbuzz-sys", "harfbuzz"),
    ("expat-sys", "expat"),
    ("zeromq-src", "libzmq"),
    ("rdkafka-sys", "librdkafka"),
    ("libduckdb-sys", "duckdb"),
    ("lua-src", "lua"),
    ("luajit-src", "luajit"),
    ("libusb1-sys", "libusb"),
    ("libpq-sys", "postgresql"),
    ("pq-src", "postgresql"),
    ("libbpf-sys", "libbpf"),
    ("libgit2-sys", "libgit2"),
    ("openblas-src", "openblas"),
    ("libopus-sys", "opus"),
    ("audiopus_sys", "opus"),
    ("libvpx-sys", "libvpx"),
    ("ffmpeg-sys-next", "ffmpeg"),
];

/// Crates that always compile their C library from source, version metadata or not.
const ALWAYS_BUNDLED: &[&str] = &[
    "openssl-src",
    "aws-lc-sys",
    "aws-lc-fips-sys",
    "boring-sys",
    "protobuf-src",
    "sqlite3-src",
    "zeromq-src",
    "hdf5-src",
    "netcdf-src",
    "lua-src",
    "luajit-src",
    "pq-src",
];

/// Crates that carry the C source but link a system copy instead when the build host
/// has one (unless a feature forces the bundled build).
const PREFERS_SYSTEM: &[&str] = &[
    "curl-sys",
    "libgit2-sys",
    "libssh2-sys",
    "bzip2-sys",
    "libz-sys",
    "libz-ng-sys",
    "lzma-sys",
    "liblzma-sys",
    "libusb1-sys",
];

/// Features that make an otherwise system-linking `-sys` crate compile its bundled copy.
fn bundles_by_feature(name: &str, features: &[String]) -> bool {
    let has = |f: &str| features.iter().any(|x| x == f);
    match name {
        "libsqlite3-sys" => has("bundled") || has("bundled-sqlcipher") || has("bundled-windows"),
        "libz-sys" => has("static"),
        "libduckdb-sys" => has("bundled"),
        "libgit2-sys" => has("vendored"),
        "libssh2-sys" => has("vendored-openssl"),
        "curl-sys" => has("static-curl"),
        "rdkafka-sys" => has("cmake-build"),
        "libusb1-sys" => has("vendored"),
        _ => false,
    }
}

/// The first `N.N[.N...]` in a string.
fn first_version(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_digit() {
            let start = i;
            while i < b.len() && (b[i].is_ascii_digit() || b[i] == b'.') {
                i += 1;
            }
            let v = s[start..i].trim_end_matches('.');
            if v.contains('.') {
                return Some(v.to_string());
            }
        } else {
            i += 1;
        }
    }
    None
}

/// The C library a `-sys`/`-src` crate compiles in, if it does.
pub fn vendored_by_crate(name: &str, version: &str, features: &[String]) -> Option<Vendored> {
    let known = SYS_LIBRARIES.iter().find(|(c, _)| *c == name).map(|x| x.1);
    let sysish = name.ends_with("-sys")
        || name.ends_with("_sys")
        || name.ends_with("-src")
        || known.is_some();
    if !sysish {
        return None;
    }
    let metadata = version.split_once('+').map(|(_, m)| m);
    // `+<upstream version>` is the convention for crates that carry the C source; for
    // crates we do not know, the metadata must look like a version (ndk-sys uses
    // `+11769913`, an NDK build number, and compiles nothing)
    let carries_version = metadata.is_some_and(|m| known.is_some() || first_version(m).is_some());
    let bundled =
        carries_version || ALWAYS_BUNDLED.contains(&name) || bundles_by_feature(name, features);
    if !bundled {
        return None;
    }
    let lib = known.map(String::from).unwrap_or_else(|| {
        name.trim_end_matches("-sys")
            .trim_end_matches("_sys")
            .trim_end_matches("-src")
            .to_string()
    });
    let mut aliases = vec![lib.clone()];
    let bare = lib.strip_prefix("lib").unwrap_or(&lib).to_string();
    if bare.len() >= 2 {
        aliases.push(bare.clone());
        aliases.push(format!("lib{bare}"));
    }
    match lib.as_str() {
        "xz" => aliases.extend(["liblzma".into(), "xz-utils".into()]),
        "sqlite" => aliases.extend(["sqlite3".into(), "libsqlite3".into()]),
        "zlib" => aliases.push("libz".into()),
        "aws-lc" => aliases.push("aws-lc-rs".into()),
        "protobuf" => aliases.push("protocolbuffers".into()),
        "postgresql" => aliases.push("libpq".into()),
        _ => {}
    }
    Some(Vendored {
        name: lib,
        version: metadata.and_then(first_version),
        evidence: if PREFERS_SYSTEM.contains(&name) && !bundles_by_feature(name, features) {
            format!(
                "crate {name} {version} links it: its bundled source, or the system library when the build host has one"
            )
        } else {
            format!("crate {name} {version} compiles it from source")
        },
        aliases,
    })
}

const VENDOR_DIRS: &[&str] = &[
    "third_party",
    "third-party",
    "thirdparty",
    "3rdparty",
    "3rd_party",
    "3rd-party",
    "vendor",
    "vendored",
    "external",
    "extern",
    "deps",
    "subprojects",
];

const SKIP_DIRS: &[&str] = &[
    ".git",
    "target",
    "node_modules",
    "build",
    "out",
    ".cargo",
    "dist",
    "test",
    "tests",
    "testdata",
    "fixtures",
    "examples",
    "docs",
];

fn is_c_source(p: &Path) -> bool {
    matches!(
        p.extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase())
            .as_deref(),
        Some("c" | "cc" | "cpp" | "cxx" | "c++" | "h" | "hh" | "hpp" | "hxx" | "s" | "asm")
    )
}

fn count_c_sources(dir: &Path, budget: &mut usize) -> usize {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut n = 0;
    for e in rd.flatten() {
        if *budget == 0 {
            break;
        }
        *budget -= 1;
        let p = e.path();
        let Ok(ft) = e.file_type() else { continue };
        if ft.is_dir() {
            n += count_c_sources(&p, budget);
        } else if ft.is_file() && is_c_source(&p) {
            n += 1;
        }
    }
    n
}

fn is_rust_or_go_package(dir: &Path) -> bool {
    [
        "Cargo.toml",
        ".cargo-checksum.json",
        "go.mod",
        "package.json",
    ]
    .iter()
    .any(|f| dir.join(f).is_file())
}

/// Submodule paths from `.gitmodules`.
fn submodules(root: &Path) -> Vec<String> {
    std::fs::read_to_string(root.join(".gitmodules"))
        .map(|t| {
            t.lines()
                .filter_map(|l| {
                    let l = l.trim();
                    l.strip_prefix("path")
                        .and_then(|r| r.trim_start().strip_prefix('='))
                        .map(|p| p.trim().replace('\\', "/"))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn walk_vendor_dirs(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if depth > 4 {
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = rd.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let Ok(ft) = e.file_type() else { continue };
        if !ft.is_dir() {
            continue;
        }
        let name = e.file_name().to_string_lossy().to_ascii_lowercase();
        if SKIP_DIRS.contains(&name.as_str()) || name.starts_with('.') {
            continue;
        }
        if VENDOR_DIRS.contains(&name.as_str()) {
            out.push(e.path());
        } else {
            walk_vendor_dirs(&e.path(), depth + 1, out);
        }
    }
}

/// Vendored C/C++ libraries in a source tree: each directory under a `third_party`,
/// `vendor`, `external`, `deps` or `subprojects` directory that holds C/C++ sources,
/// single-file libraries placed directly in one, and submodules registered under one
/// (counted even when not checked out).
pub fn scan_vendored(root: &Path) -> Vec<Vendored> {
    let mut dirs = Vec::new();
    walk_vendor_dirs(root, 0, &mut dirs);
    let subs = submodules(root);
    let rel = |p: &Path| {
        p.strip_prefix(root)
            .unwrap_or(p)
            .to_string_lossy()
            .replace('\\', "/")
    };
    let mut out: BTreeMap<String, Vendored> = BTreeMap::new();
    let mut add = |name: &str, evidence: String| {
        let name = name.to_ascii_lowercase();
        if name.len() < 2 {
            return;
        }
        out.entry(name.clone()).or_insert_with(|| {
            let bare = name.strip_prefix("lib").unwrap_or(&name).to_string();
            let mut aliases = vec![name.clone()];
            if bare.len() >= 2 && bare != name {
                aliases.push(bare);
            }
            Vendored {
                name,
                version: None,
                evidence,
                aliases,
            }
        });
    };
    for d in &dirs {
        let Ok(rd) = std::fs::read_dir(d) else {
            continue;
        };
        let mut entries: Vec<_> = rd.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let p = e.path();
            let Ok(ft) = e.file_type() else { continue };
            let fname = e.file_name().to_string_lossy().to_string();
            if ft.is_dir() {
                if fname.starts_with('.') || is_rust_or_go_package(&p) {
                    continue;
                }
                let r = rel(&p);
                let mut budget = 50_000;
                let n = count_c_sources(&p, &mut budget);
                if n > 0 {
                    add(&fname, format!("{r} ({n} C/C++ files)"));
                } else if subs.iter().any(|s| s == &r) {
                    add(&fname, format!("{r} (git submodule, not checked out)"));
                }
            } else if ft.is_file() && is_c_source(&p) {
                let ext = p.extension().and_then(|x| x.to_str()).unwrap_or("");
                if matches!(ext, "c" | "cc" | "cpp" | "cxx") {
                    let stem = p
                        .file_stem()
                        .map(|s| s.to_string_lossy().to_string())
                        .unwrap_or_default();
                    add(&stem, format!("{} (single-file library)", rel(&p)));
                }
            }
        }
    }
    out.into_values().collect()
}

/// A third-party native component the C/C++ build saw (from compile_commands, the
/// build log or a linker map).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeComponent {
    pub name: String,
    pub version: Option<String>,
    pub evidence: String,
}

/// Everything known about what the build really contains.
#[derive(Clone, Debug, Default)]
pub struct Truth {
    /// Cargo.lock path and packages.
    pub lock: Option<(String, Vec<LockPackage>)>,
    /// How the graph was resolved ("cargo tree --target all") and its crates.
    pub graph: Option<(String, Vec<GraphCrate>)>,
    pub native: Vec<NativeComponent>,
    pub vendored: Vec<Vendored>,
    /// Inputs that were scanned and found nothing, for the report.
    pub notes: Vec<String>,
}

/// One registry index entry for a crate version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexEntry {
    pub yanked: bool,
    pub cksum: Option<String>,
}

/// Registry facts per (crate, version). None means the check could not run.
pub type IndexFacts = HashMap<(String, String), IndexEntry>;

/// Path of a crate in the sparse index layout.
pub fn index_path(name: &str) -> String {
    let n = name.to_ascii_lowercase();
    match n.len() {
        0 => String::new(),
        1 => format!("1/{n}"),
        2 => format!("2/{n}"),
        3 => format!("3/{}/{n}", &n[..1]),
        _ => format!("{}/{}/{n}", &n[..2], &n[2..4]),
    }
}

/// Parse one sparse-index file (one JSON object per line).
pub fn parse_index_file(text: &str, facts: &mut IndexFacts) {
    for line in text.lines() {
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let (Some(name), Some(vers)) = (v["name"].as_str(), v["vers"].as_str()) else {
            continue;
        };
        facts.insert(
            (name.to_string(), vers.to_string()),
            IndexEntry {
                yanked: v["yanked"].as_bool().unwrap_or(false),
                cksum: v["cksum"].as_str().map(String::from),
            },
        );
    }
}

/// Fetch the crates.io sparse index entries for these crate names, with one `curl
/// --parallel` run. Fails when curl is missing or nothing could be fetched.
pub fn fetch_index(names: &BTreeSet<String>, index_url: &str) -> Result<IndexFacts> {
    let mut facts = IndexFacts::new();
    if names.is_empty() {
        return Ok(facts);
    }
    let dir = std::env::temp_dir().join(format!("sbom-attest-index-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let slash = |p: &Path| p.to_string_lossy().replace('\\', "/");
    let names: Vec<&String> = names.iter().collect();
    let mut cfg = String::new();
    for (i, n) in names.iter().enumerate() {
        cfg.push_str(&format!(
            "url = \"{}/{}\"\noutput = \"{}/{i}.jsonl\"\n",
            index_url.trim_end_matches('/'),
            index_path(n),
            slash(&dir)
        ));
    }
    let cfg_path = dir.join("curl.cfg");
    std::fs::write(&cfg_path, cfg)?;
    let status = Command::new("curl")
        .args([
            "--parallel",
            "--parallel-max",
            "24",
            "--silent",
            "--fail",
            "--location",
            "--compressed",
            "--retry",
            "2",
            "--user-agent",
            concat!(
                "sbom-attest/",
                env!("CARGO_PKG_VERSION"),
                " (https://github.com/Mattbusel/sbom-attest)"
            ),
            "--config",
        ])
        .arg(&cfg_path)
        .status();
    let mut fetched = 0;
    for i in 0..names.len() {
        if let Ok(t) = std::fs::read_to_string(dir.join(format!("{i}.jsonl"))) {
            fetched += 1;
            parse_index_file(&t, &mut facts);
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    match status {
        Err(e) => bail!("curl is needed to query {index_url}: {e}"),
        Ok(_) if fetched == 0 => bail!("no index entries could be fetched from {index_url}"),
        Ok(_) => Ok(facts),
    }
}

/// Normalised cargo crate name (crates.io treats `-` and `_` as the same).
fn crate_key(name: &str) -> String {
    name.to_ascii_lowercase().replace('_', "-")
}

/// Lowercase alphanumerics only, for matching C library names.
fn alnum(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase()
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hex = std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("");
            if let Ok(x) = u8::from_str_radix(hex, 16) {
                out.push(x);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// (type, name without namespace, version) of a purl.
pub fn purl_parts(purl: &str) -> Option<(String, String, Option<String>)> {
    let rest = purl.strip_prefix("pkg:")?;
    let rest = rest.split(['?', '#']).next().unwrap_or(rest);
    let (ty, path) = rest.split_once('/')?;
    let (path, version) = match path.rfind('@') {
        Some(i) => (&path[..i], Some(percent_decode(&path[i + 1..]))),
        None => (path, None),
    };
    let name = path.rsplit('/').next().unwrap_or(path);
    Some((
        ty.to_ascii_lowercase(),
        percent_decode(name),
        version.filter(|v| !v.is_empty()),
    ))
}

fn is_cargo_component(c: &DocComponent) -> bool {
    c.purl
        .as_deref()
        .and_then(purl_parts)
        .is_some_and(|(t, _, _)| t == "cargo")
}

/// The version an SBOM gives a component: the version field, else the purl's.
fn doc_version(c: &DocComponent) -> Option<String> {
    c.version.clone().or_else(|| {
        c.purl
            .as_deref()
            .and_then(purl_parts)
            .and_then(|(_, _, v)| v)
    })
}

fn doc_crate_name(c: &DocComponent) -> String {
    c.purl
        .as_deref()
        .and_then(purl_parts)
        .filter(|(t, _, _)| t == "cargo")
        .map(|(_, n, _)| n)
        .unwrap_or_else(|| c.name.clone())
}

/// A version string that does not pin one exact version.
pub fn is_unpinned_version(v: Option<&str>) -> bool {
    let Some(v) = v.map(str::trim) else {
        return true;
    };
    if v.is_empty() {
        return true;
    }
    let lower = v.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "*" | "latest" | "unknown" | "noassertion" | "none" | "x" | "master" | "main" | "head"
    ) {
        return true;
    }
    v.contains(['^', '~', '*', '>', '<', '|', ' ']) || v.starts_with('=') || lower.ends_with(".x")
}

/// What to check, and what was waived.
#[derive(Clone, Debug, Default)]
pub struct AuditOptions {
    pub waived: BTreeSet<Class>,
}

/// The audit result.
#[derive(Clone, Debug, Default)]
pub struct AuditReport {
    pub sbom: String,
    pub sbom_format: String,
    pub sbom_tool: Option<String>,
    pub sbom_components: usize,
    /// What the SBOM was checked against.
    pub inputs: Vec<String>,
    pub findings: Vec<Finding>,
    pub waived: BTreeSet<Class>,
    /// Checks that could not run, and why. Each fails the audit unless waived.
    pub not_run: Vec<(Class, String)>,
    pub notes: Vec<String>,
}

impl AuditReport {
    pub fn count(&self, class: Class) -> usize {
        self.findings.iter().filter(|f| f.class == class).count()
    }

    /// Findings and checks-not-run that are not waived.
    pub fn failures(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| !self.waived.contains(&f.class))
            .count()
            + self
                .not_run
                .iter()
                .filter(|(c, _)| !self.waived.contains(c))
                .count()
    }

    pub fn passed(&self) -> bool {
        self.failures() == 0
    }

    fn status(&self, class: Class) -> &'static str {
        let n = self.count(class);
        let not_run = self.not_run.iter().any(|(c, _)| *c == class);
        if self.waived.contains(&class) {
            "WAIVED"
        } else if not_run {
            "NOT RUN (fails)"
        } else if n > 0 {
            "FAIL"
        } else {
            "pass"
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "tool": format!("sbom-attest {}", env!("CARGO_PKG_VERSION")),
            "result": if self.passed() { "pass" } else { "fail" },
            "failures": self.failures(),
            "sbom": {
                "path": self.sbom,
                "format": self.sbom_format,
                "tool": self.sbom_tool,
                "components": self.sbom_components,
            },
            "checkedAgainst": self.inputs,
            "checks": Class::ALL.iter().map(|c| json!({
                "check": c.as_str(),
                "status": self.status(*c),
                "findings": self.count(*c),
                "meaning": c.meaning(),
            })).collect::<Vec<_>>(),
            "waived": self.waived.iter().map(|c| json!({"check": c.as_str(), "cost": c.waiver_cost()})).collect::<Vec<_>>(),
            "notRun": self.not_run.iter().map(|(c, why)| json!({"check": c.as_str(), "reason": why})).collect::<Vec<_>>(),
            "findings": self.findings.iter().map(|f| json!({
                "check": f.class.as_str(),
                "name": f.name,
                "version": f.version,
                "detail": f.detail,
                "evidence": f.evidence,
            })).collect::<Vec<_>>(),
            "notes": self.notes,
        })
    }

    pub fn to_markdown(&self) -> String {
        let mut s = format!(
            "# sbom-attest audit: {}\n\n",
            if self.passed() {
                "PASS".to_string()
            } else {
                format!(
                    "FAIL ({} finding{})",
                    self.failures(),
                    if self.failures() == 1 { "" } else { "s" }
                )
            }
        );
        s.push_str(&format!(
            "SBOM: `{}` ({}, {} components{})\n\n",
            self.sbom,
            self.sbom_format,
            self.sbom_components,
            self.sbom_tool
                .as_ref()
                .map(|t| format!(", made by {t}"))
                .unwrap_or_default()
        ));
        if self.inputs.is_empty() {
            s.push_str("Checked against: nothing the build produced.\n\n");
        } else {
            s.push_str("Checked against:\n\n");
            for i in &self.inputs {
                s.push_str(&format!("- {i}\n"));
            }
            s.push('\n');
        }
        s.push_str("| Check | Result | Findings | Means |\n|---|---|---|---|\n");
        for c in Class::ALL {
            s.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                c.as_str(),
                self.status(c),
                self.count(c),
                c.meaning()
            ));
        }
        if !self.waived.is_empty() {
            s.push_str("\n**Waived checks.** This SBOM was not verified for:\n\n");
            for c in &self.waived {
                s.push_str(&format!("- `{}`: {}\n", c.as_str(), c.waiver_cost()));
            }
        }
        if !self.not_run.is_empty() {
            s.push_str("\n**Checks that could not run** (an unverified claim fails):\n\n");
            for (c, why) in &self.not_run {
                s.push_str(&format!("- `{}`: {why}\n", c.as_str()));
            }
        }
        for c in Class::ALL {
            let items: Vec<&Finding> = self.findings.iter().filter(|f| f.class == c).collect();
            if items.is_empty() {
                continue;
            }
            s.push_str(&format!("\n## {}: {}\n\n", c.as_str(), c.meaning()));
            for f in items {
                s.push_str(&format!(
                    "- `{}{}`: {} ({})\n",
                    f.name,
                    f.version
                        .as_ref()
                        .map(|v| format!(" {v}"))
                        .unwrap_or_default(),
                    f.detail,
                    f.evidence
                ));
            }
        }
        if !self.notes.is_empty() {
            s.push_str("\n## Notes\n\n");
            for n in &self.notes {
                s.push_str(&format!("- {n}\n"));
            }
        }
        s
    }
}

/// Run every check. `index` is the registry facts for crates.io crates, or the reason
/// they could not be fetched.
pub fn audit(
    sbom_path: &str,
    doc: &Doc,
    truth: &Truth,
    index: std::result::Result<&IndexFacts, String>,
    opts: &AuditOptions,
) -> AuditReport {
    let mut r = AuditReport {
        sbom: sbom_path.to_string(),
        sbom_format: format!("{} {}", doc.format, doc.format_version)
            .trim()
            .to_string(),
        sbom_tool: doc.tool_name.as_ref().map(|n| {
            format!(
                "{n}{}",
                doc.tool_version
                    .as_ref()
                    .map(|v| format!(" {v}"))
                    .unwrap_or_default()
            )
        }),
        sbom_components: doc.components.len(),
        waived: opts.waived.clone(),
        notes: truth.notes.clone(),
        ..Default::default()
    };
    fn push(r: &mut AuditReport, f: Finding) {
        if !r.findings.contains(&f) {
            r.findings.push(f);
        }
    }

    // the SBOM's cargo components by crate name; components without a purl count
    // when their name is a crate in Cargo.lock
    let lock_names: BTreeSet<String> = truth
        .lock
        .iter()
        .flat_map(|(_, p)| p.iter().map(|p| crate_key(&p.name)))
        .collect();
    let mut sbom_crates: BTreeMap<String, Vec<&DocComponent>> = BTreeMap::new();
    for c in &doc.components {
        let cargo =
            is_cargo_component(c) || (c.purl.is_none() && lock_names.contains(&crate_key(&c.name)));
        if cargo {
            sbom_crates
                .entry(crate_key(&doc_crate_name(c)))
                .or_default()
                .push(c);
        }
    }
    let lock_index: HashMap<(String, String), &LockPackage> = truth
        .lock
        .iter()
        .flat_map(|(_, p)| p.iter())
        .map(|p| ((crate_key(&p.name), p.version.clone()), p))
        .collect();

    // what the build contains: the resolved graph when there is one, else Cargo.lock
    struct T {
        name: String,
        version: String,
        origin: Origin,
        build_only: bool,
        features: Vec<String>,
        evidence: String,
    }
    let mut built: Vec<T> = Vec::new();
    if let Some((desc, g)) = &truth.graph {
        r.inputs.push(format!("{desc} ({} crates)", g.len()));
        built.extend(g.iter().map(|c| T {
            name: c.name.clone(),
            version: c.version.clone(),
            origin: c.origin.clone(),
            build_only: c.build_only,
            features: c.features.clone(),
            evidence: desc.clone(),
        }));
    }
    if let Some((path, pkgs)) = &truth.lock {
        r.inputs.push(format!("{path} ({} packages)", pkgs.len()));
        if truth.graph.is_none() {
            r.notes.push(
                "No crate graph was resolved, so Cargo.lock stands in for it: dev-only and other-platform crates count as built. Pass --manifest-path for the exact graph.".into(),
            );
            built.extend(pkgs.iter().map(|p| T {
                name: p.name.clone(),
                version: p.version.clone(),
                origin: p.origin(),
                build_only: false,
                features: Vec::new(),
                evidence: path.clone(),
            }));
        }
    }
    if !truth.native.is_empty() {
        r.inputs.push(format!(
            "C/C++ build inputs ({} third-party components)",
            truth.native.len()
        ));
    }
    if built.is_empty() && truth.native.is_empty() && truth.vendored.is_empty() {
        r.not_run.push((
            Class::Omitted,
            "no build evidence was given: pass --manifest-path, --lockfile, --binary, --compile-commands or --source-dir".into(),
        ));
    }

    // omitted, version drift, hash drift, unhashed
    let mut drifted: BTreeSet<String> = BTreeSet::new();
    let mut path_crates = 0;
    for t in &built {
        if t.origin == Origin::Path {
            path_crates += 1;
            continue;
        }
        let key = crate_key(&t.name);
        let Some(cands) = sbom_crates.get(&key) else {
            let class = if t.build_only {
                Class::OmittedBuild
            } else {
                Class::Omitted
            };
            push(
                &mut r,
                Finding {
                    class,
                    name: t.name.clone(),
                    version: Some(t.version.clone()),
                    detail: if t.build_only {
                        "build-time dependency the SBOM does not list".into()
                    } else {
                        "in the build, not in the SBOM".into()
                    },
                    evidence: t.evidence.clone(),
                },
            );
            continue;
        };
        let Some(c) = cands
            .iter()
            .find(|c| doc_version(c).as_deref() == Some(t.version.as_str()))
        else {
            drifted.insert(key.clone());
            let declared: Vec<String> = cands
                .iter()
                .map(|c| doc_version(c).unwrap_or_else(|| "(no version)".into()))
                .collect();
            push(
                &mut r,
                Finding {
                    class: Class::VersionDrift,
                    name: t.name.clone(),
                    version: Some(t.version.clone()),
                    detail: format!(
                        "the build uses {}, the SBOM says {}",
                        t.version,
                        declared.join(", ")
                    ),
                    evidence: t.evidence.clone(),
                },
            );
            continue;
        };
        let lock_sum = lock_index
            .get(&(key.clone(), t.version.clone()))
            .and_then(|p| p.checksum.clone());
        let registry_sum = match (&index, &t.origin) {
            (Ok(facts), Origin::CratesIo) => facts
                .get(&(t.name.clone(), t.version.clone()))
                .and_then(|e| e.cksum.clone()),
            _ => None,
        };
        let (pinned, pinned_by) = match (lock_sum, registry_sum) {
            (Some(s), _) => (Some(s), "Cargo.lock"),
            (None, Some(s)) => (Some(s), "the crates.io index"),
            _ => (None, ""),
        };
        if let Some(sum) = pinned {
            match c.hashes.get("SHA-256") {
                Some(h) if !h.eq_ignore_ascii_case(&sum) => push(
                    &mut r,
                    Finding {
                        class: Class::HashDrift,
                        name: t.name.clone(),
                        version: Some(t.version.clone()),
                        detail: format!("SBOM SHA-256 {h}, {pinned_by} pins {sum}"),
                        evidence: pinned_by.into(),
                    },
                ),
                Some(_) => {}
                None if c.hashes.is_empty() => push(
                    &mut r,
                    Finding {
                        class: Class::Unhashed,
                        name: t.name.clone(),
                        version: Some(t.version.clone()),
                        detail: format!("no hash in the SBOM; {pinned_by} pins sha256 {sum}"),
                        evidence: pinned_by.into(),
                    },
                ),
                None => {}
            }
        }
    }
    if path_crates > 0 {
        r.notes.push(format!(
            "{path_crates} path crate(s) (workspace members, local path dependencies) are first party and were not required in the SBOM."
        ));
    }

    // vendored C/C++ under crate names, and in the source tree
    let mut vendored: Vec<Vendored> = Vec::new();
    for t in &built {
        if let Some(v) = vendored_by_crate(&t.name, &t.version, &t.features) {
            if !vendored.iter().any(|x| x.name == v.name) {
                vendored.push(v);
            }
        }
    }
    vendored.extend(truth.vendored.iter().cloned());
    if !truth.vendored.is_empty() {
        r.inputs.push(format!(
            "source tree ({} vendored C/C++ librar{})",
            truth.vendored.len(),
            if truth.vendored.len() == 1 {
                "y"
            } else {
                "ies"
            }
        ));
    }
    for v in &vendored {
        let aliases: BTreeSet<String> = v.aliases.iter().map(|a| alnum(a)).collect();
        let matches: Vec<&DocComponent> = doc
            .components
            .iter()
            .filter(|c| {
                // the wrapper crate itself does not count as naming the C library
                let wrapper = is_cargo_component(c);
                let n = alnum(&c.name);
                let cpe_hit = c.cpe.as_deref().is_some_and(|cpe| {
                    cpe.split(':')
                        .nth(4)
                        .is_some_and(|p| aliases.contains(&alnum(p)))
                });
                !wrapper && (aliases.contains(&n) || cpe_hit)
            })
            .collect();
        if matches.is_empty() {
            push(
                &mut r,
                Finding {
                    class: Class::VendoredC,
                    name: v.name.clone(),
                    version: v.version.clone(),
                    detail: "compiled into the build; no SBOM component names it".into(),
                    evidence: v.evidence.clone(),
                },
            );
        } else if let Some(want) = &v.version {
            let have: Vec<String> = matches.iter().filter_map(|c| doc_version(c)).collect();
            if !have.is_empty() && !have.iter().any(|h| h == want || h.starts_with(want)) {
                push(
                    &mut r,
                    Finding {
                        class: Class::VersionDrift,
                        name: v.name.clone(),
                        version: Some(want.clone()),
                        detail: format!(
                            "the build compiles {want}, the SBOM says {}",
                            have.join(", ")
                        ),
                        evidence: v.evidence.clone(),
                    },
                );
            }
        }
    }

    // native components the C/C++ build saw
    for n in &truth.native {
        let key = alnum(&n.name);
        let hits: Vec<&DocComponent> = doc
            .components
            .iter()
            .filter(|c| alnum(&c.name) == key)
            .collect();
        if hits.is_empty() {
            push(
                &mut r,
                Finding {
                    class: Class::Omitted,
                    name: n.name.clone(),
                    version: n.version.clone(),
                    detail: "in the C/C++ build, not in the SBOM".into(),
                    evidence: n.evidence.clone(),
                },
            );
        } else if let Some(want) = &n.version {
            if !hits
                .iter()
                .any(|c| doc_version(c).as_deref() == Some(want.as_str()))
            {
                push(
                    &mut r,
                    Finding {
                        class: Class::VersionDrift,
                        name: n.name.clone(),
                        version: Some(want.clone()),
                        detail: format!(
                            "the build uses {want}, the SBOM says {}",
                            hits.iter()
                                .map(|c| doc_version(c).unwrap_or_else(|| "(no version)".into()))
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                        evidence: n.evidence.clone(),
                    },
                );
            }
        }
    }

    // phantom: declared crates the build does not contain
    let graph_set: Option<BTreeSet<(String, String)>> = truth.graph.as_ref().map(|(_, g)| {
        g.iter()
            .map(|c| (crate_key(&c.name), c.version.clone()))
            .collect()
    });
    let lock_set: Option<BTreeSet<(String, String)>> = truth.lock.as_ref().map(|(_, p)| {
        p.iter()
            .map(|p| (crate_key(&p.name), p.version.clone()))
            .collect()
    });
    for (key, cands) in &sbom_crates {
        if drifted.contains(key) {
            continue;
        }
        for c in cands {
            let Some(v) = doc_version(c) else { continue };
            let k = (key.clone(), v.clone());
            let detail = match (&lock_set, &graph_set) {
                (Some(l), _) if !l.contains(&k) => Some("not in Cargo.lock".to_string()),
                (_, Some(g)) if !g.contains(&k) => Some(format!(
                    "in Cargo.lock but not in {} (a dev-only or other-platform crate)",
                    truth
                        .graph
                        .as_ref()
                        .map(|g| g.0.as_str())
                        .unwrap_or("the graph")
                )),
                (None, None) => None,
                _ => None,
            };
            if let Some(detail) = detail {
                push(
                    &mut r,
                    Finding {
                        class: Class::Phantom,
                        name: doc_crate_name(c),
                        version: Some(v),
                        detail,
                        evidence: "SBOM".into(),
                    },
                );
            }
        }
    }

    // unpinned and unlicensed components, root included
    for c in doc.root.iter().chain(doc.components.iter()) {
        let v = doc_version(c);
        if is_unpinned_version(v.as_deref()) {
            push(
                &mut r,
                Finding {
                    class: Class::Unpinned,
                    name: c.name.clone(),
                    version: v.clone(),
                    detail: match &v {
                        None => "no version".into(),
                        Some(v) => format!("version `{v}` is not one exact version"),
                    },
                    evidence: "SBOM".into(),
                },
            );
        }
        if c.license.is_none() {
            push(
                &mut r,
                Finding {
                    class: Class::NoLicense,
                    name: c.name.clone(),
                    version: v,
                    detail: "no license".into(),
                    evidence: "SBOM".into(),
                },
            );
        }
    }

    // yanked crates: what the build uses, plus crates.io crates only the SBOM names
    match index {
        Err(why) => r.not_run.push((Class::Yanked, why)),
        Ok(facts) => {
            let mut seen = BTreeSet::new();
            let mut check = |r: &mut AuditReport, name: &str, version: &str, ev: &str| {
                if !seen.insert((name.to_string(), version.to_string())) {
                    return;
                }
                if facts
                    .get(&(name.to_string(), version.to_string()))
                    .is_some_and(|e| e.yanked)
                {
                    push(
                        r,
                        Finding {
                            class: Class::Yanked,
                            name: name.to_string(),
                            version: Some(version.to_string()),
                            detail: "yanked on crates.io".into(),
                            evidence: ev.to_string(),
                        },
                    );
                }
            };
            for t in built.iter().filter(|t| t.origin == Origin::CratesIo) {
                check(&mut r, &t.name, &t.version, &t.evidence);
            }
            for c in doc.components.iter().filter(|c| is_cargo_component(c)) {
                if let Some(v) = doc_version(c) {
                    check(&mut r, &doc_crate_name(c), &v, "SBOM");
                }
            }
        }
    }
    r
}

/// The target an SBOM says it was generated for: cargo-cyclonedx records
/// `cdx:rustc:sbom:target:triple` or `cdx:rustc:sbom:target:all_targets`. Returns
/// `all`, a triple, or None when the SBOM does not say.
pub fn recorded_target(sbom: &Value) -> Option<String> {
    let m = &sbom["metadata"];
    let props = m["properties"]
        .as_array()
        .into_iter()
        .chain(m["component"]["properties"].as_array())
        .flatten();
    let mut triple = None;
    for p in props {
        match (p["name"].as_str(), p["value"].as_str()) {
            (Some("cdx:rustc:sbom:target:all_targets"), Some("true")) => return Some("all".into()),
            (Some("cdx:rustc:sbom:target:triple"), Some(t)) if !t.is_empty() => {
                triple = Some(t.to_string())
            }
            _ => {}
        }
    }
    triple
}

/// crates.io crate names an audit needs index facts for.
pub fn crates_io_names(doc: &Doc, truth: &Truth) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    match (&truth.graph, &truth.lock) {
        (Some((_, g)), _) => out.extend(
            g.iter()
                .filter(|c| c.origin == Origin::CratesIo)
                .map(|c| c.name.clone()),
        ),
        (None, Some((_, p))) => out.extend(
            p.iter()
                .filter(|p| p.origin() == Origin::CratesIo)
                .map(|p| p.name.clone()),
        ),
        _ => {}
    }
    for c in &doc.components {
        if is_cargo_component(c) {
            out.insert(doc_crate_name(c));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const LOCK: &str = r#"version = 4

[[package]]
name = "app"
version = "0.1.0"
dependencies = ["serde", "openssl-src"]

[[package]]
name = "serde"
version = "1.0.210"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaa"

[[package]]
name = "openssl-src"
version = "300.3.1+3.3.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "bbbb"

[[package]]
name = "time"
version = "0.3.20"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "cccc"

[[package]]
name = "proptest"
version = "1.4.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "dddd"

[[package]]
name = "gitdep"
version = "0.1.0"
source = "git+https://github.com/x/gitdep?rev=abc#abcdef0123"
"#;

    fn comp(name: &str, ver: Option<&str>, hash: Option<&str>, lic: Option<&str>) -> DocComponent {
        let mut c = DocComponent {
            name: name.into(),
            version: ver.map(String::from),
            purl: Some(match ver {
                Some(v) => format!("pkg:cargo/{name}@{}", v.replace('+', "%2B")),
                None => format!("pkg:cargo/{name}"),
            }),
            license: lic.map(String::from),
            ..Default::default()
        };
        if let Some(h) = hash {
            c.hashes.insert("SHA-256".into(), h.into());
        }
        c
    }

    fn graph() -> Vec<GraphCrate> {
        let g = |n: &str, v: &str, b: bool| GraphCrate {
            name: n.into(),
            version: v.into(),
            origin: Origin::CratesIo,
            build_only: b,
            features: vec![],
        };
        vec![
            GraphCrate {
                origin: Origin::Path,
                ..g("app", "0.1.0", false)
            },
            g("serde", "1.0.210", false),
            g("openssl-src", "300.3.1+3.3.1", true),
            g("time", "0.3.20", false),
            GraphCrate {
                origin: Origin::Git("https://github.com/x/gitdep#abcdef0123".into()),
                ..g("gitdep", "0.1.0", false)
            },
        ]
    }

    fn truth() -> Truth {
        Truth {
            lock: Some(("Cargo.lock".into(), parse_lock(LOCK))),
            graph: Some(("cargo tree --target all".into(), graph())),
            ..Default::default()
        }
    }

    fn classes(r: &AuditReport) -> BTreeMap<&'static str, Vec<String>> {
        let mut m: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
        for f in &r.findings {
            m.entry(f.class.as_str()).or_default().push(f.name.clone());
        }
        m
    }

    #[test]
    fn parses_lock_including_legacy_checksums() {
        let p = parse_lock(LOCK);
        assert_eq!(p.len(), 6);
        assert_eq!(p[0].origin(), Origin::Path);
        assert_eq!(p[1].checksum.as_deref(), Some("aaaa"));
        assert_eq!(p[5].origin(), Origin::Git(p[5].source.clone().unwrap()));
        let legacy = "[[package]]\nname = \"a\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n[metadata]\n\"checksum a 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)\" = \"ffff\"\n";
        let p = parse_lock(legacy);
        assert_eq!(p[0].checksum.as_deref(), Some("ffff"));
    }

    #[test]
    fn a_faithful_sbom_passes() {
        let doc = Doc {
            format: "CycloneDX".into(),
            root: Some(comp("app", Some("0.1.0"), None, Some("MIT"))),
            components: vec![
                comp(
                    "serde",
                    Some("1.0.210"),
                    Some("aaaa"),
                    Some("MIT OR Apache-2.0"),
                ),
                comp(
                    "openssl-src",
                    Some("300.3.1+3.3.1"),
                    Some("bbbb"),
                    Some("MIT OR Apache-2.0"),
                ),
                DocComponent {
                    name: "openssl".into(),
                    version: Some("3.3.1".into()),
                    purl: Some("pkg:generic/openssl@3.3.1".into()),
                    license: Some("Apache-2.0".into()),
                    ..Default::default()
                },
                comp("time", Some("0.3.20"), Some("cccc"), Some("MIT")),
                comp("gitdep", Some("0.1.0"), Some("eeee"), Some("MIT")),
            ],
            ..Default::default()
        };
        let facts = IndexFacts::new();
        let r = audit(
            "s.json",
            &doc,
            &truth(),
            Ok(&facts),
            &AuditOptions::default(),
        );
        assert!(r.passed(), "{}", r.to_markdown());
    }

    #[test]
    fn a_lying_sbom_fails_on_every_class() {
        let doc = Doc {
            format: "CycloneDX".into(),
            root: Some(comp("app", Some("0.1.0"), None, None)),
            components: vec![
                // wrong hash
                comp("serde", Some("1.0.210"), Some("9999"), Some("MIT")),
                // wrapper only: the C library is never named; no hash
                comp("openssl-src", Some("300.3.1+3.3.1"), None, Some("MIT")),
                // stale version
                comp("time", Some("0.3.17"), None, Some("MIT")),
                // dev-only crate claimed as shipped
                comp("proptest", Some("1.4.0"), Some("dddd"), Some("MIT")),
                // never existed in this build
                comp("left-pad", Some("1.0.0"), None, Some("MIT")),
                // range, no license
                DocComponent {
                    name: "zlib".into(),
                    version: Some("^1.2".into()),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let mut facts = IndexFacts::new();
        facts.insert(
            ("serde".into(), "1.0.210".into()),
            IndexEntry {
                yanked: true,
                cksum: Some("aaaa".into()),
            },
        );
        let r = audit(
            "s.json",
            &doc,
            &truth(),
            Ok(&facts),
            &AuditOptions::default(),
        );
        let m = classes(&r);
        assert_eq!(m["hash-drift"], vec!["serde"]);
        assert_eq!(m["vendored-c"], vec!["openssl"]);
        assert_eq!(m["version-drift"], vec!["time"]);
        assert_eq!(m["omitted"], vec!["gitdep"]);
        assert_eq!(m["unhashed"], vec!["openssl-src"]);
        assert_eq!(m["yanked"], vec!["serde"]);
        assert_eq!(m["phantom"], vec!["left-pad", "proptest"]);
        assert_eq!(m["unpinned"], vec!["zlib"]);
        assert_eq!(m["no-license"], vec!["app", "zlib"]);
        assert!(!m.contains_key("omitted-build"));
        let vc = r
            .findings
            .iter()
            .find(|f| f.class == Class::VendoredC)
            .unwrap();
        assert_eq!(vc.version.as_deref(), Some("3.3.1"));
        assert!(!r.passed());
        let md = r.to_markdown();
        assert!(md.starts_with("# sbom-attest audit: FAIL"));
        assert!(md.contains("the build uses 0.3.20, the SBOM says 0.3.17"));
        assert_eq!(r.to_json()["result"], "fail");
    }

    #[test]
    fn missing_build_dependency_is_its_own_class() {
        let doc = Doc {
            components: vec![
                comp("serde", Some("1.0.210"), Some("aaaa"), Some("MIT")),
                comp("time", Some("0.3.20"), Some("cccc"), Some("MIT")),
                comp("gitdep", Some("0.1.0"), Some("e"), Some("MIT")),
            ],
            ..Default::default()
        };
        let facts = IndexFacts::new();
        let r = audit("s", &doc, &truth(), Ok(&facts), &AuditOptions::default());
        let m = classes(&r);
        assert_eq!(m["omitted-build"], vec!["openssl-src"]);
        assert_eq!(m["vendored-c"], vec!["openssl"]);
    }

    #[test]
    fn waivers_are_explicit_and_unrun_checks_fail() {
        let doc = Doc {
            components: vec![comp("serde", Some("1.0.210"), Some("aaaa"), None)],
            ..Default::default()
        };
        let t = Truth {
            lock: Some((
                "Cargo.lock".into(),
                parse_lock(
                    "[[package]]\nname = \"serde\"\nversion = \"1.0.210\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"aaaa\"\n",
                ),
            )),
            ..Default::default()
        };
        let r = audit(
            "s",
            &doc,
            &t,
            Err("offline".into()),
            &AuditOptions::default(),
        );
        assert_eq!(r.count(Class::NoLicense), 1);
        assert_eq!(r.failures(), 2, "{}", r.to_markdown());
        let waived = AuditOptions {
            waived: [Class::NoLicense, Class::Yanked].into_iter().collect(),
        };
        let r = audit("s", &doc, &t, Err("offline".into()), &waived);
        assert!(r.passed());
        let md = r.to_markdown();
        assert!(md.contains("WAIVED"));
        assert!(md.contains("does NOT fail on yanked crates"));
    }

    #[test]
    fn nothing_to_check_against_fails() {
        let doc = Doc::default();
        let facts = IndexFacts::new();
        let r = audit(
            "s",
            &doc,
            &Truth::default(),
            Ok(&facts),
            &AuditOptions::default(),
        );
        assert!(!r.passed());
        assert_eq!(r.not_run[0].0, Class::Omitted);
    }

    #[test]
    fn sys_crates_name_their_c_library() {
        let v = vendored_by_crate("zstd-sys", "2.0.13+zstd.1.5.6", &[]).unwrap();
        assert_eq!(
            (v.name.as_str(), v.version.as_deref()),
            ("zstd", Some("1.5.6"))
        );
        let v = vendored_by_crate("tikv-jemalloc-sys", "0.6.0+5.3.0-1-ge13ca99", &[]).unwrap();
        assert_eq!(
            (v.name.as_str(), v.version.as_deref()),
            ("jemalloc", Some("5.3.0"))
        );
        let v = vendored_by_crate("curl-sys", "0.4.74+curl-8.9.0", &[]).unwrap();
        assert_eq!(v.version.as_deref(), Some("8.9.0"));
        assert!(v.evidence.contains("or the system library"));
        let v =
            vendored_by_crate("curl-sys", "0.4.74+curl-8.9.0", &["static-curl".into()]).unwrap();
        assert!(v.evidence.contains("compiles it from source"));
        assert!(vendored_by_crate("libsqlite3-sys", "0.30.1", &[]).is_none());
        let v = vendored_by_crate("libsqlite3-sys", "0.30.1", &["bundled".into()]).unwrap();
        assert_eq!(v.name, "sqlite");
        assert!(v.aliases.contains(&"sqlite3".to_string()));
        assert!(vendored_by_crate("aws-lc-sys", "0.24.0", &[]).is_some());
        assert!(vendored_by_crate("serde", "1.0.0+x", &[]).is_none());
        assert!(vendored_by_crate("ndk-sys", "0.6.0+11769913", &[]).is_none());
        let v = vendored_by_crate("foo-sys", "0.1.0+2.4.1", &[]).unwrap();
        assert_eq!(
            (v.name.as_str(), v.version.as_deref()),
            ("foo", Some("2.4.1"))
        );
    }

    #[test]
    fn cpe_names_the_library() {
        let doc = Doc {
            components: vec![DocComponent {
                name: "OpenSSL Project OpenSSL".into(),
                version: Some("3.3.1".into()),
                cpe: Some("cpe:2.3:a:openssl:openssl:3.3.1:*:*:*:*:*:*:*".into()),
                license: Some("Apache-2.0".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        let t = Truth {
            vendored: vec![vendored_by_crate("openssl-src", "300.3.1+3.3.1", &[]).unwrap()],
            ..Default::default()
        };
        let facts = IndexFacts::new();
        let r = audit("s", &doc, &t, Ok(&facts), &AuditOptions::default());
        assert_eq!(r.count(Class::VendoredC), 0, "{}", r.to_markdown());
    }

    #[test]
    fn graph_marks_proc_macros_and_build_deps() {
        let normal = "0app v0.1.0 (/w/app)|\n1serde v1.0.210|default\n2serde_derive v1.0.210 (proc-macro)|default\n";
        let full = "0app v0.1.0 (/w/app)|\n1serde v1.0.210|default,derive\n2serde_derive v1.0.210 (proc-macro)|default\n1cc v1.1.0|\n";
        let g = graph_from_trees(normal, full);
        let get = |n: &str| g.iter().find(|c| c.name == n).unwrap();
        assert_eq!(get("app").origin, Origin::Path);
        assert!(!get("serde").build_only);
        assert!(get("serde_derive").build_only);
        assert!(get("cc").build_only);
        assert_eq!(get("serde").features, vec!["default", "derive"]);
    }

    #[test]
    fn reads_the_recorded_target() {
        let v = json!({"metadata": {"component": {"properties": [
            {"name": "cdx:rustc:sbom:target:triple", "value": "x86_64-unknown-linux-gnu"}]}}});
        assert_eq!(
            recorded_target(&v).as_deref(),
            Some("x86_64-unknown-linux-gnu")
        );
        let v = json!({"metadata": {"properties": [
            {"name": "cdx:rustc:sbom:target:all_targets", "value": "true"}]}});
        assert_eq!(recorded_target(&v).as_deref(), Some("all"));
        assert_eq!(recorded_target(&json!({})), None);
    }

    #[test]
    fn index_layout_and_parse() {
        assert_eq!(index_path("a"), "1/a");
        assert_eq!(index_path("cc"), "2/cc");
        assert_eq!(index_path("syn"), "3/s/syn");
        assert_eq!(index_path("Serde"), "se/rd/serde");
        let mut f = IndexFacts::new();
        parse_index_file(
            "{\"name\":\"serde\",\"vers\":\"1.0.0\",\"cksum\":\"ab\",\"yanked\":false}\n{\"name\":\"serde\",\"vers\":\"1.0.1\",\"cksum\":\"cd\",\"yanked\":true}\n",
            &mut f,
        );
        assert!(f[&("serde".to_string(), "1.0.1".to_string())].yanked);
        assert_eq!(
            f[&("serde".to_string(), "1.0.0".to_string())]
                .cksum
                .as_deref(),
            Some("ab")
        );
    }

    #[test]
    fn purls_and_versions() {
        assert_eq!(
            purl_parts("pkg:cargo/openssl-src@300.3.1%2B3.3.1?x=y"),
            Some((
                "cargo".into(),
                "openssl-src".into(),
                Some("300.3.1+3.3.1".into())
            ))
        );
        assert_eq!(
            purl_parts("pkg:github/actions/checkout@v4"),
            Some(("github".into(), "checkout".into(), Some("v4".into())))
        );
        for v in ["^1.2", "~1", "*", ">=1, <2", "latest", "1.x", ""] {
            assert!(is_unpinned_version(Some(v)), "{v}");
        }
        assert!(is_unpinned_version(None));
        for v in [
            "1.2.3",
            "0.4.74+curl-8.9.0",
            "v4",
            "2024-01-01",
            "3.3.1-beta",
        ] {
            assert!(!is_unpinned_version(Some(v)), "{v}");
        }
        assert_eq!(Class::parse("no_license").unwrap(), Class::NoLicense);
        assert!(Class::parse("everything").is_err());
    }

    #[test]
    fn scans_vendored_source_tree() {
        let d = std::env::temp_dir().join(format!("sbom-attest-vendored-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let mk = |p: &str, body: &str| {
            let p = d.join(p);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, body).unwrap();
        };
        mk("third_party/zlib/inflate.c", "int x;");
        mk("third_party/zlib/zlib.h", "");
        mk("src/vendor/miniz.c", "int y;");
        mk("vendor/serde/Cargo.toml", "[package]");
        mk("vendor/serde/src/x.c", "");
        mk("tests/third_party/gtest/gtest.cc", "");
        mk(
            ".gitmodules",
            "[submodule \"abseil\"]\n\tpath = third_party/abseil-cpp\n\turl = https://x\n",
        );
        std::fs::create_dir_all(d.join("third_party/abseil-cpp")).unwrap();
        let v = scan_vendored(&d);
        let names: Vec<&str> = v.iter().map(|v| v.name.as_str()).collect();
        assert_eq!(names, vec!["abseil-cpp", "miniz", "zlib"]);
        assert!(v[2].evidence.contains("third_party/zlib (2 C/C++ files)"));
        assert!(v[0].evidence.contains("submodule"));
        let _ = std::fs::remove_dir_all(&d);
    }
}
