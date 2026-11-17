//! # sbom-attest
//!
//! Build-time SBOMs for mixed Rust and C/C++ (including embedded) builds.
//!
//! - Rust components come from `cargo metadata` and `cargo tree` (so target-conditional
//!   features are resolved for the real `--target`), with crate hashes from
//!   `Cargo.lock`, and from the dependency list cargo-auditable embeds in a binary.
//! - C/C++ components come from `compile_commands.json` and the depfiles the compiler
//!   wrote, the build log's link and archive lines, and GNU ld / lld linker maps,
//!   which name every archive member the linker actually pulled in.
//! - Output is CycloneDX 1.6 JSON and SPDX 2.3 JSON with the CISA 2026 minimum
//!   elements (hash and algorithm, tool name and version, generation context, author
//!   signature), signed with ECDSA P-256 (JSF inside the CycloneDX document, plus
//!   detached signatures that `cosign verify-blob` checks).
//! - `diff` compares a vendor SBOM with an independently built one; `attest` writes
//!   in-toto / SLSA v1 provenance in a DSSE envelope; `bundle --profile dowi-8430`
//!   writes a release evidence bundle indexed to DoWI 8430.01.

pub mod binary;
pub mod bundle;
pub mod cargo_src;
pub mod cc;
pub mod cdx;
pub mod check;
pub mod model;
pub mod provenance;
pub mod read;
pub mod sign;
pub mod spdx;
pub mod util;

use anyhow::Result;
use model::{Component, Inventory, Kind, Lang, Phase};
use std::path::{Path, PathBuf};

/// Everything `generate` needs.
#[derive(Clone, Debug, Default)]
pub struct GenerateOptions {
    pub cargo: Option<cargo_src::CargoOptions>,
    pub project_root: Option<PathBuf>,
    pub name: Option<String>,
    pub version: Option<String>,
    pub firmware: bool,
    pub compile_commands: Option<PathBuf>,
    pub build_log: Option<PathBuf>,
    pub link_maps: Vec<PathBuf>,
    pub binary: Option<PathBuf>,
    pub build_dir: Option<PathBuf>,
    pub producer: Option<String>,
    pub use_dpkg: bool,
    pub author: Option<String>,
    pub timestamp: Option<i64>,
    pub memsafe: bool,
}

fn git_describe(dir: &Path) -> Option<String> {
    let o = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["describe", "--tags", "--always", "--dirty"])
        .output()
        .ok()?;
    if !o.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&o.stdout).trim().to_string()).filter(|v| !v.is_empty())
}

fn host_triple() -> Option<String> {
    let o = std::process::Command::new("rustc")
        .arg("-vV")
        .output()
        .ok()?;
    String::from_utf8_lossy(&o.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("host: ").map(|s| s.trim().to_string()))
}

/// Give every component at least one identifier: a `pkg:generic` purl carrying the
/// version, the git commit or the file checksum when there is no ecosystem purl.
fn fill_identifiers(c: &mut Component) {
    if c.purl.is_some() {
        return;
    }
    let mut q = Vec::new();
    if let Some(commit) = c.properties.get("sbom-attest:git-commit") {
        q.push(format!("vcs_url=git%2B{}", util::purl_escape(commit)));
    }
    if let Some(h) = c.sha256() {
        if matches!(
            c.hash_subject.as_deref(),
            Some("archive" | "shared-object" | "binary")
        ) {
            q.push(format!("checksum=sha256:{h}"));
        }
    }
    let name = util::purl_escape(&c.name.replace('/', "_"));
    let mut p = format!("pkg:generic/{name}");
    if let Some(v) = &c.version {
        p.push('@');
        p.push_str(&util::purl_escape(v));
    }
    if !q.is_empty() {
        p.push('?');
        p.push_str(&q.join("&"));
    }
    c.purl = Some(p);
}

/// Build the inventory from every input given.
pub fn generate(o: &GenerateOptions) -> Result<Inventory> {
    let ts = util::timestamp(o.timestamp);
    let cwd = std::env::current_dir()?;
    let mut project_root = o
        .project_root
        .clone()
        .map(|p| util::normalize(&cwd.join(p)));

    let mut inv = if let Some(copts) = &o.cargo {
        let scan = cargo_src::scan(copts)?;
        if project_root.is_none() {
            project_root = Some(util::normalize(&scan.workspace_root));
        }
        let mut inv = Inventory::new(scan.root.clone(), ts);
        inv.target = copts.target.clone().or_else(host_triple);
        cargo_src::apply(&mut inv, scan);
        inv
    } else {
        let root_dir = project_root.clone().unwrap_or_else(|| cwd.clone());
        let name = o.name.clone().unwrap_or_else(|| {
            root_dir
                .file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_else(|| "project".into())
        });
        let mut root = Component::new(
            format!("src:{name}"),
            if o.firmware {
                Kind::Firmware
            } else {
                Kind::Application
            },
            &name,
        );
        root.lang = Lang::C;
        project_root = Some(root_dir);
        Inventory::new(root, ts)
    };
    let project_root = project_root.unwrap_or(cwd);
    if let Some(v) = &o.version {
        inv.root.version = Some(v.clone());
    }
    if let Some(n) = &o.name {
        if o.cargo.is_some() {
            inv.root.name = n.clone();
        }
    }
    if o.firmware {
        inv.root.kind = Kind::Firmware;
    }
    if let Some(p) = &o.producer {
        inv.root.producer = Some(p.clone());
    }
    if inv.root.version.is_none() {
        inv.root.version = git_describe(&project_root);
    }
    if inv.root.license.is_none() && o.cargo.is_none() {
        if let Some((l, from)) = cc::project_license(&project_root) {
            inv.root.license = Some(l);
            inv.root
                .properties
                .insert("sbom-attest:license-detected-from".into(), from);
        }
    }

    if o.compile_commands.is_some() || o.build_log.is_some() || !o.link_maps.is_empty() {
        cc::scan(
            &mut inv,
            &cc::CcOptions {
                project_root: project_root.clone(),
                compile_commands: o.compile_commands.clone(),
                build_log: o.build_log.clone(),
                build_dir: o.build_dir.clone(),
                link_maps: o.link_maps.clone(),
                binary: o.binary.clone(),
                use_dpkg: o.use_dpkg,
            },
        )?;
    }
    if let Some(b) = &o.binary {
        let info = binary::analyze(b)?;
        binary::apply(&mut inv, b, &info);
        let origin = b.parent().map(|p| p.to_path_buf()).unwrap_or_default();
        let runpaths: Vec<PathBuf> = info
            .runpaths
            .iter()
            .map(|r| PathBuf::from(r.replace("$ORIGIN", &util::slash(&origin))))
            .collect();
        cc::resolve_needed(&mut inv, &project_root, &runpaths, o.use_dpkg)?;
    }
    inv.author = o.author.clone();
    if inv.phases.is_empty() {
        inv.phases.insert(Phase::PreBuild);
    }
    if o.memsafe {
        inv.mark_memsafe();
    }
    fill_identifiers(&mut inv.root);
    for c in inv.components.values_mut() {
        fill_identifiers(c);
    }
    let unhashed = inv.unhashed().len();
    if unhashed > 0 {
        inv.unknowns.push(format!(
            "{unhashed} component(s) have no hash: no artifact was available to hash (marked sbom-attest:hash=unknown)"
        ));
    }
    Ok(inv)
}

/// Write `data` to `path`, creating parent directories.
pub fn write(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(p) = path.parent() {
        if !p.as_os_str().is_empty() {
            std::fs::create_dir_all(p)?;
        }
    }
    std::fs::write(path, data)?;
    Ok(())
}

/// Pretty JSON with a trailing newline.
pub fn pretty(v: &serde_json::Value) -> Vec<u8> {
    let mut s = serde_json::to_vec_pretty(v).unwrap_or_default();
    s.push(b'\n');
    s
}
