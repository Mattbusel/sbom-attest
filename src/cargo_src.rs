//! Rust components from `cargo metadata`, `cargo tree` and `Cargo.lock`.
//!
//! The dependency graph and the enabled features come from `cargo tree`, because it runs
//! cargo's real feature resolver for the requested `--target`. `cargo metadata` unifies
//! features across every platform even with `--filter-platform`
//! (rust-lang/cargo#9863), so an SBOM built from its resolve graph alone lists crates
//! that a target-conditional feature never pulls in. `cargo metadata` still supplies
//! the package details (license, authors, repository, targets).

use crate::model::{Component, Inventory, Kind, Lang, Phase, Scope};
use crate::util::{purl_escape, spdx_expression};
use anyhow::{anyhow, bail, Context, Result};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::process::Command;

/// How to run `cargo metadata` / `cargo tree`. Build it with [`CargoOptions::new`]
/// or a struct literal ending in `..Default::default()`.
#[derive(Clone, Debug, Default)]
pub struct CargoOptions {
    pub manifest_path: PathBuf,
    /// Workspace packages that produce the artifact. Several (a release archive of
    /// several binaries) are described under one product root.
    pub packages: Vec<String>,
    pub target: Option<String>,
    pub features: Vec<String>,
    pub all_features: bool,
    pub no_default_features: bool,
    pub offline: bool,
    pub locked: bool,
}

impl CargoOptions {
    /// Options for the Cargo project at `manifest_path`, everything else default.
    pub fn new(manifest_path: impl Into<PathBuf>) -> Self {
        CargoOptions {
            manifest_path: manifest_path.into(),
            ..Default::default()
        }
    }

    fn common(&self, cmd: &mut Command) {
        cmd.arg("--manifest-path").arg(&self.manifest_path);
        if !self.features.is_empty() {
            cmd.arg("--features").arg(self.features.join(","));
        }
        if self.all_features {
            cmd.arg("--all-features");
        }
        if self.no_default_features {
            cmd.arg("--no-default-features");
        }
        if self.offline {
            cmd.arg("--offline");
        }
        if self.locked {
            cmd.arg("--locked");
        }
    }
}

fn cargo() -> Command {
    Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
}

fn run(mut cmd: Command) -> Result<String> {
    let out = cmd.output().with_context(|| format!("running {cmd:?}"))?;
    if !out.status.success() {
        bail!(
            "{:?} failed: {}",
            cmd,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8(out.stdout)?)
}

/// One package as `cargo tree` printed it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeNode {
    pub depth: usize,
    pub name: String,
    pub version: String,
    /// The parenthesised source cargo prints for anything that is not crates.io.
    pub source: Option<String>,
    pub features: Vec<String>,
}

/// Parse `cargo tree --prefix depth --charset ascii -f '{p}|{f}'` output.
pub fn parse_tree(text: &str) -> Vec<TreeNode> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim_end();
        let digits: String = line.chars().take_while(|c| c.is_ascii_digit()).collect();
        if digits.is_empty() {
            continue;
        }
        let rest = &line[digits.len()..];
        let (pkg, feats) = match rest.rsplit_once('|') {
            Some((p, f)) => (p, f),
            None => (rest, ""),
        };
        let feats = feats.trim().trim_end_matches("(*)").trim();
        let pkg = pkg.trim().trim_end_matches("(*)").trim();
        let pkg = pkg.trim_end_matches("(proc-macro)").trim();
        let mut parts = pkg.splitn(3, ' ');
        let name = parts.next().unwrap_or_default().to_string();
        let version = parts
            .next()
            .unwrap_or_default()
            .trim_start_matches('v')
            .to_string();
        let source = parts
            .next()
            .map(|s| {
                s.trim()
                    .trim_start_matches('(')
                    .trim_end_matches(')')
                    .to_string()
            })
            .filter(|s| !s.is_empty() && s != "*" && s != "proc-macro");
        if name.is_empty() || version.is_empty() {
            continue;
        }
        out.push(TreeNode {
            depth: digits.parse().unwrap_or(0),
            name,
            version,
            source,
            features: feats
                .split(',')
                .map(str::trim)
                .filter(|f| !f.is_empty())
                .map(String::from)
                .collect(),
        });
    }
    out
}

/// Turn a depth-prefixed listing into parent -> child edges between node indices.
pub fn tree_edges(nodes: &[TreeNode]) -> Vec<(usize, usize)> {
    let mut stack: Vec<usize> = Vec::new();
    let mut edges = Vec::new();
    for (i, n) in nodes.iter().enumerate() {
        stack.truncate(n.depth);
        if let Some(&parent) = stack.last() {
            edges.push((parent, i));
        }
        stack.push(i);
    }
    edges
}

/// `name version -> sha256` from Cargo.lock.
pub fn lock_checksums(text: &str) -> HashMap<(String, String), String> {
    let mut out = HashMap::new();
    let (mut name, mut version, mut sum) = (None, None, None);
    let mut flush = |n: &mut Option<String>, v: &mut Option<String>, s: &mut Option<String>| {
        if let (Some(n), Some(v), Some(s)) = (n.take(), v.take(), s.take()) {
            out.insert((n, v), s);
        }
    };
    for line in text.lines() {
        let line = line.trim();
        if line == "[[package]]" {
            flush(&mut name, &mut version, &mut sum);
            continue;
        }
        let value = |l: &str| {
            l.split_once('=')
                .map(|(_, v)| v.trim().trim_matches('"').to_string())
        };
        if line.starts_with("name ") || line.starts_with("name=") {
            name = value(line);
        } else if line.starts_with("version ") || line.starts_with("version=") {
            version = value(line);
        } else if line.starts_with("checksum ") || line.starts_with("checksum=") {
            sum = value(line);
        }
    }
    flush(&mut name, &mut version, &mut sum);
    out
}

fn strip_email(author: &str) -> String {
    match author.find('<') {
        Some(i) => author[..i].trim().to_string(),
        None => author.trim().to_string(),
    }
}

/// Stable component id for a cargo package.
fn cargo_id(name: &str, version: &str, source: Option<&str>) -> String {
    match source {
        None => format!("pkg:cargo/{name}@{version}"),
        Some(s) if s.starts_with("registry+") && s.contains("crates.io") => {
            format!("pkg:cargo/{name}@{version}")
        }
        Some(s) if s.starts_with("git+") => {
            let short: String = s
                .rsplit('#')
                .next()
                .unwrap_or("")
                .chars()
                .take(12)
                .collect();
            format!("cargo:{name}@{version}+git.{short}")
        }
        Some(_) => format!("cargo:{name}@{version}+local"),
    }
}

struct Pkg<'a> {
    v: &'a Value,
}

impl<'a> Pkg<'a> {
    fn s(&self, k: &str) -> Option<&'a str> {
        self.v.get(k).and_then(Value::as_str)
    }
    fn source(&self) -> Option<&'a str> {
        self.s("source")
    }
    fn is_proc_macro(&self) -> bool {
        self.v["targets"].as_array().is_some_and(|ts| {
            ts.iter().any(|t| {
                t["kind"]
                    .as_array()
                    .is_some_and(|k| k.iter().any(|x| x == "proc-macro"))
            })
        })
    }
    fn has_bin(&self) -> bool {
        self.v["targets"].as_array().is_some_and(|ts| {
            ts.iter().any(|t| {
                t["kind"]
                    .as_array()
                    .is_some_and(|k| k.iter().any(|x| x == "bin"))
            })
        })
    }
}

fn component_for(p: &Pkg, checksum: Option<&String>, features: &[String]) -> Component {
    let name = p.s("name").unwrap_or_default();
    let version = p.s("version").unwrap_or_default();
    let source = p.source();
    let mut c = Component::new(cargo_id(name, version, source), Kind::Library, name);
    c.version = Some(version.to_string());
    c.lang = Lang::Rust;
    c.purl = Some(match source {
        Some(s) if s.starts_with("git+") => format!(
            "pkg:cargo/{}@{}?vcs_url={}",
            purl_escape(name),
            purl_escape(version),
            purl_escape(s)
        ),
        _ => format!("pkg:cargo/{}@{}", purl_escape(name), purl_escape(version)),
    });
    if let Some(sum) = checksum {
        c.hashes.push(("SHA-256".into(), sum.clone()));
        c.hash_subject = Some("crate-archive".into());
    }
    c.license = p.s("license").map(spdx_expression);
    if c.license.is_none() && p.s("license_file").is_some() {
        c.properties
            .insert("sbom-attest:license-file".into(), "declared".into());
    }
    let authors: Vec<String> = p.v["authors"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(strip_email)
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();
    if !authors.is_empty() {
        c.producer = Some(authors.join(", "));
    }
    c.description = p
        .s("description")
        .map(|d| d.split_whitespace().collect::<Vec<_>>().join(" "));
    if let Some(r) = p.s("repository") {
        c.external_refs.push(("vcs".into(), r.to_string()));
    }
    if let Some(h) = p.s("homepage") {
        c.external_refs.push(("website".into(), h.to_string()));
    }
    if let Some(d) = p.s("documentation") {
        c.external_refs
            .push(("documentation".into(), d.to_string()));
    }
    if let Some(l) = p.s("links") {
        c.properties
            .insert("sbom-attest:cargo:links".into(), l.to_string());
    }
    if !features.is_empty() {
        c.properties
            .insert("sbom-attest:cargo:features".into(), features.join(","));
    }
    match source {
        None => {
            c.properties
                .insert("sbom-attest:cargo:source".into(), "path".into());
        }
        Some(s) => {
            c.properties
                .insert("sbom-attest:cargo:source".into(), s.to_string());
        }
    }
    c.evidence.insert("cargo-metadata".into());
    c.evidence.insert("cargo-tree".into());
    c
}

/// Everything the Rust side found.
pub struct CargoScan {
    pub root: Component,
    pub components: Vec<Component>,
    pub edges: BTreeSet<(String, String)>,
    pub workspace_root: PathBuf,
}

pub fn scan(opts: &CargoOptions) -> Result<CargoScan> {
    let mut cmd = cargo();
    cmd.args(["metadata", "--format-version", "1"]);
    if let Some(t) = &opts.target {
        cmd.arg("--filter-platform").arg(t);
    }
    opts.common(&mut cmd);
    let meta: Value = serde_json::from_str(&run(cmd)?).context("parsing cargo metadata")?;
    let workspace_root = PathBuf::from(
        meta["workspace_root"]
            .as_str()
            .ok_or_else(|| anyhow!("cargo metadata has no workspace_root"))?,
    );

    let packages: Vec<Pkg> = meta["packages"]
        .as_array()
        .ok_or_else(|| anyhow!("cargo metadata has no packages"))?
        .iter()
        .map(|v| Pkg { v })
        .collect();

    // the root packages: --package, else the resolve root
    let local = |name: &str| -> Result<&Pkg> {
        packages
            .iter()
            .find(|p| p.s("name") == Some(name) && p.source().is_none())
            .ok_or_else(|| anyhow!("no workspace package named {name}"))
    };
    let root_pkgs: Vec<&Pkg> = if opts.packages.is_empty() {
        let id = meta["resolve"]["root"].as_str().ok_or_else(|| {
            anyhow!("this is a virtual workspace: pass --package to pick the artifact")
        })?;
        vec![packages
            .iter()
            .find(|p| p.s("id") == Some(id))
            .ok_or_else(|| anyhow!("root package missing from metadata"))?]
    } else {
        opts.packages
            .iter()
            .map(|n| local(n))
            .collect::<Result<_>>()?
    };
    let root_names: Vec<String> = root_pkgs
        .iter()
        .map(|p| p.s("name").unwrap_or_default().to_string())
        .collect();

    let lock_path = workspace_root.join("Cargo.lock");
    let checksums = std::fs::read_to_string(&lock_path)
        .map(|t| lock_checksums(&t))
        .unwrap_or_default();

    let tree = |edges: &str| -> Result<Vec<TreeNode>> {
        let mut cmd = cargo();
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
        for n in &root_names {
            cmd.arg("--package").arg(n);
        }
        // without --target, cargo tree resolves for the host, which is what gets built
        if let Some(t) = &opts.target {
            cmd.arg("--target").arg(t);
        }
        opts.common(&mut cmd);
        Ok(parse_tree(&run(cmd)?))
    };
    let runtime = tree("normal")?;
    let full = tree("normal,build")?;

    // (name, version) -> metadata packages
    let mut by_nv: HashMap<(&str, &str), Vec<&Pkg>> = HashMap::new();
    for p in &packages {
        by_nv
            .entry((
                p.s("name").unwrap_or_default(),
                p.s("version").unwrap_or_default(),
            ))
            .or_default()
            .push(p);
    }
    let resolve = |n: &TreeNode| -> Option<&Pkg> {
        let cands = by_nv.get(&(n.name.as_str(), n.version.as_str()))?;
        if cands.len() == 1 {
            return Some(cands[0]);
        }
        match &n.source {
            None => cands
                .iter()
                .find(|p| p.source().is_some_and(|s| s.contains("crates.io")))
                .copied(),
            Some(src) => cands
                .iter()
                .find(|p| match p.source() {
                    None => p
                        .s("manifest_path")
                        .is_some_and(|m| Path::new(m).starts_with(src)),
                    Some(s) => s.contains(src.as_str()) || src.contains(s),
                })
                .copied()
                .or(Some(cands[0])),
        }
    };

    let runtime_ids: BTreeSet<String> = runtime
        .iter()
        .filter_map(&resolve)
        .filter(|p| !p.is_proc_macro())
        .map(|p| cargo_id(p.s("name").unwrap(), p.s("version").unwrap(), p.source()))
        .collect();

    let mut comps: BTreeMap<String, Component> = BTreeMap::new();
    let mut ids: Vec<Option<String>> = Vec::new();
    let mut edges = BTreeSet::new();
    for n in &full {
        let Some(p) = resolve(n) else {
            ids.push(None);
            continue;
        };
        let id = cargo_id(p.s("name").unwrap(), p.s("version").unwrap(), p.source());
        let mut c = component_for(
            p,
            checksums.get(&(n.name.clone(), n.version.clone())),
            &n.features,
        );
        if !runtime_ids.contains(&id) {
            c.scope = Scope::Excluded;
            c.properties.insert(
                "sbom-attest:cargo:dependency-kind".into(),
                if p.is_proc_macro() {
                    "proc-macro"
                } else {
                    "build"
                }
                .into(),
            );
        }
        let scope = c.scope;
        comps.entry(id.clone()).or_insert(c);
        if let Some(v) = vendored_component(p, &n.features, scope) {
            edges.insert((id.clone(), v.id.clone()));
            comps.entry(v.id.clone()).or_insert(v);
        }
        ids.push(Some(id));
    }
    for (a, b) in tree_edges(&full) {
        if let (Some(a), Some(b)) = (&ids[a], &ids[b]) {
            edges.insert((a.clone(), b.clone()));
        }
    }

    let root = if let [root_pkg] = root_pkgs[..] {
        let root_cid = cargo_id(
            root_pkg.s("name").unwrap_or_default(),
            root_pkg.s("version").unwrap_or_default(),
            None,
        );
        let mut root = comps
            .remove(&root_cid)
            .unwrap_or_else(|| component_for(root_pkg, None, &[]));
        root.kind = if root_pkg.has_bin() {
            Kind::Application
        } else {
            Kind::Library
        };
        root.scope = Scope::Required;
        if root.hashes.is_empty() {
            if let Some(manifest) = root_pkg.s("manifest_path") {
                if let Some(h) = package_source_digest(Path::new(manifest), opts.offline) {
                    root.hashes.push(("SHA-256".into(), h.0));
                    root.hash_subject = Some("source-files".into());
                    root.properties
                        .insert("sbom-attest:file-count".into(), h.1.to_string());
                }
            }
        }
        root
    } else {
        // several packages ship together: a product root that depends on each of them
        let name = workspace_root
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_else(|| "workspace".into());
        let mut root = Component::new(format!("src:{name}"), Kind::Application, &name);
        root.version = root_pkgs[0].s("version").map(String::from);
        root.lang = Lang::Rust;
        root.evidence.insert("cargo-metadata".into());
        // the product carries the packages' license when they all declare the same one
        let licenses: BTreeSet<_> = root_pkgs.iter().map(|p| p.s("license")).collect();
        if let [Some(l)] = licenses.into_iter().collect::<Vec<_>>()[..] {
            root.license = Some(spdx_expression(l));
        }
        for p in &root_pkgs {
            let cid = cargo_id(
                p.s("name").unwrap_or_default(),
                p.s("version").unwrap_or_default(),
                None,
            );
            if let Some(c) = comps.get_mut(&cid) {
                c.scope = Scope::Required;
                if p.has_bin() {
                    c.kind = Kind::Application;
                }
            }
            edges.insert((root.id.clone(), cid));
        }
        root
    };

    Ok(CargoScan {
        root,
        components: comps.into_values().collect(),
        edges,
        workspace_root,
    })
}

/// SPDX licenses of C libraries that `-sys`/`-src` crates compile in.
const VENDORED_LICENSES: &[(&str, &str)] = &[
    ("sqlite", "blessing"),
    ("openssl", "Apache-2.0"),
    ("zlib", "Zlib"),
    ("zstd", "BSD-3-Clause OR GPL-2.0-only"),
    ("lz4", "BSD-2-Clause"),
    ("bzip2", "bzip2-1.0.6"),
    ("xz", "0BSD"),
    ("jemalloc", "BSD-2-Clause"),
    ("mimalloc", "MIT"),
    ("curl", "curl"),
    ("libssh2", "BSD-3-Clause"),
    ("nghttp2", "MIT"),
    ("aws-lc", "ISC AND (Apache-2.0 OR ISC)"),
    ("boringssl", "ISC"),
];

/// The C library a `-sys`/`-src` crate compiles into the build, as its own component,
/// so the SBOM names what CVE scanners look for (sqlite, not libsqlite3-sys).
fn vendored_component(p: &Pkg, features: &[String], scope: Scope) -> Option<Component> {
    let name = p.s("name")?;
    let version = p.s("version")?;
    let v = crate::audit::vendored_by_crate(name, version, features)?;
    let dir = p.s("manifest_path").and_then(|m| Path::new(m).parent());
    let lib_version = v
        .version
        .clone()
        .or_else(|| dir.and_then(|d| bundled_version(&v.name, d)));
    let mut c = Component::new(format!("vendored:{}", v.name), Kind::Library, &v.name);
    c.version = lib_version;
    c.lang = Lang::C;
    c.scope = scope;
    c.license = VENDORED_LICENSES
        .iter()
        .find(|(l, _)| *l == v.name)
        .map(|(_, s)| s.to_string());
    c.purl = Some(match &c.version {
        Some(ver) => format!("pkg:generic/{}@{}", purl_escape(&v.name), purl_escape(ver)),
        None => format!("pkg:generic/{}", purl_escape(&v.name)),
    });
    c.evidence.insert("cargo-tree".into());
    c.properties.insert(
        "sbom-attest:vendored-by".into(),
        format!("{name} {version}"),
    );
    Some(c)
}

/// The version of a C library bundled in a crate's source, when its header states it.
fn bundled_version(lib: &str, crate_dir: &Path) -> Option<String> {
    let (header, define) = match lib {
        "sqlite" => ("sqlite3/sqlite3.h", "SQLITE_VERSION"),
        "aws-lc" => (
            "aws-lc/include/openssl/base.h",
            "AWSLC_VERSION_NUMBER_STRING",
        ),
        _ => return None,
    };
    parse_define_version(
        &std::fs::read_to_string(crate_dir.join(header)).ok()?,
        define,
    )
}

fn parse_define_version(text: &str, define: &str) -> Option<String> {
    text.lines().find_map(|l| {
        let rest = l.trim().strip_prefix("#define")?.trim_start();
        let rest = rest.strip_prefix(define)?;
        if !rest.starts_with(char::is_whitespace) {
            return None;
        }
        let v = rest.trim().trim_matches('"');
        (!v.is_empty() && v.contains('.')).then(|| v.to_string())
    })
}

/// Digest of the files `cargo package` would ship (sbom-attest's tree digest), for a
/// package that has no built artifact to hash. Returns (digest, file count).
fn package_source_digest(manifest: &Path, offline: bool) -> Option<(String, usize)> {
    let dir = manifest.parent()?;
    let mut cmd = cargo();
    cmd.args(["package", "--list", "--allow-dirty", "--manifest-path"])
        .arg(manifest)
        .current_dir(dir);
    if offline {
        cmd.arg("--offline");
    }
    let out = cmd.output().ok()?;
    if !out.status.success() {
        return None;
    }
    let mut files = Vec::new();
    for rel in String::from_utf8_lossy(&out.stdout).lines() {
        let rel = rel.trim();
        let p = dir.join(rel);
        if rel.is_empty() || !p.is_file() {
            continue; // generated entries (Cargo.toml.orig, .cargo_vcs_info.json)
        }
        files.push((rel.replace('\\', "/"), crate::util::sha256_file(&p).ok()?));
    }
    if files.is_empty() {
        return None;
    }
    Some((crate::util::tree_digest(&files), files.len()))
}

/// Merge a scan into an inventory whose root is the cargo root.
pub fn apply(inv: &mut Inventory, scan: CargoScan) {
    let root_id = scan.root.id.clone();
    inv.add(scan.root);
    for c in scan.components {
        inv.add(c);
    }
    for (a, b) in scan.edges {
        let a = if a == root_id { inv.root.id.clone() } else { a };
        inv.depend(&a, &b);
    }
    inv.phases.insert(Phase::PreBuild);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendored_c_library_becomes_a_component() {
        let sqlite = serde_json::json!({"name": "libsqlite3-sys", "version": "0.30.1"});
        let pkg = Pkg { v: &sqlite };
        assert!(vendored_component(&pkg, &[], Scope::Required).is_none());
        let c = vendored_component(&pkg, &["bundled".into()], Scope::Required).unwrap();
        assert_eq!(c.name, "sqlite");
        assert_eq!(c.license.as_deref(), Some("blessing"));
        assert_eq!(c.lang, Lang::C);
        let openssl = serde_json::json!({"name": "openssl-src", "version": "300.3.1+3.3.1"});
        let pkg = Pkg { v: &openssl };
        let c = vendored_component(&pkg, &[], Scope::Required).unwrap();
        assert_eq!(c.version.as_deref(), Some("3.3.1"));
        assert_eq!(c.purl.as_deref(), Some("pkg:generic/openssl@3.3.1"));
        assert_eq!(
            parse_define_version(
                "#define SQLITE_VERSION        \"3.46.0\"
#define SQLITE_VERSION_NUMBER 3046000",
                "SQLITE_VERSION"
            ),
            Some("3.46.0".into())
        );
        let dir = std::env::temp_dir().join("sbom-attest-awslc-header");
        std::fs::create_dir_all(dir.join("aws-lc/include/openssl")).unwrap();
        std::fs::write(
            dir.join("aws-lc/include/openssl/base.h"),
            "#define AWSLC_VERSION_NUMBER_STRING \"5.7.0\"
",
        )
        .unwrap();
        assert_eq!(bundled_version("aws-lc", &dir), Some("5.7.0".into()));
    }

    #[test]
    fn parses_depth_prefixed_tree() {
        let text = "0app v0.1.0 (/w/app)|\n1lib v0.1.0 (/w/lib)|\n2serde v1.0.200|default,derive,std\n3serde_derive v1.0.200 (proc-macro)|default\n2libc v0.2.150|default (*)\n\n0other v1.0.0|\n";
        let nodes = parse_tree(text);
        assert_eq!(nodes.len(), 6);
        assert_eq!(nodes[0].source.as_deref(), Some("/w/app"));
        assert_eq!(nodes[2].features, vec!["default", "derive", "std"]);
        assert_eq!(nodes[3].name, "serde_derive");
        assert_eq!(nodes[3].source, None);
        assert_eq!(nodes[4].features, vec!["default"]);
        assert_eq!(tree_edges(&nodes), vec![(0, 1), (1, 2), (2, 3), (1, 4)]);
    }

    #[test]
    fn reads_lock_checksums() {
        let lock = "version = 4\n\n[[package]]\nname = \"a\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"abc\"\n\n[[package]]\nname = \"local\"\nversion = \"0.1.0\"\n";
        let m = lock_checksums(lock);
        assert_eq!(m.get(&("a".into(), "1.0.0".into())).unwrap(), "abc");
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn ids_by_source() {
        assert_eq!(
            cargo_id(
                "a",
                "1.0.0",
                Some("registry+https://github.com/rust-lang/crates.io-index")
            ),
            "pkg:cargo/a@1.0.0"
        );
        assert_eq!(cargo_id("a", "1.0.0", None), "pkg:cargo/a@1.0.0");
        assert_eq!(
            cargo_id("a", "1.0.0", Some("git+https://x/y?rev=1#0123456789abcdef")),
            "cargo:a@1.0.0+git.0123456789ab"
        );
        assert_eq!(strip_email("Ann <a@b.c>"), "Ann");
    }
}
