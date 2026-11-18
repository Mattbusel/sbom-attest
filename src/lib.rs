//! # sbom-attest
//!
//! Build-time SBOMs for mixed Rust and C/C++ (including embedded) builds, as a
//! library and as the `sbom-attest` CLI.
//!
//! ## Use it as a library
//!
//! ```no_run
//! let inv = sbom_attest::generate(&sbom_attest::GenerateOptions::cargo("Cargo.toml"))?;
//! let cyclonedx = sbom_attest::to_cyclonedx(&inv); // serde_json::Value, CycloneDX 1.6
//! let spdx = sbom_attest::to_spdx(&inv, "https://example.com/spdxdocs"); // SPDX 2.3
//! sbom_attest::write("target/sbom.cdx.json", &sbom_attest::pretty(&cyclonedx))?;
//! # let _ = spdx;
//! # Ok::<(), anyhow::Error>(())
//! ```
//!
//! With `default-features = false` the crate depends only on `anyhow`, `serde_json`
//! and `sha2`. Optional features:
//!
//! | feature  | adds | extra deps |
//! |----------|------|------------|
//! | `sign`   | `sign` module: P-256 keys, cosign-compatible detached signatures, DSSE, JSF | `p256`, `rand_core`, `base64` |
//! | `binary` | `binary` module: hash ELF/PE/Mach-O, read cargo-auditable data and `DT_NEEDED` | `goblin`, `miniz_oxide` |
//! | `cli` (default) | the `sbom-attest` binary; enables `sign` and `binary` | `clap` |
//!
//! The stable surface is the items at the crate root: [`generate`],
//! [`GenerateOptions`], [`CargoOptions`], [`Inventory`], [`to_cyclonedx`],
//! [`to_spdx`], [`load_sbom`], [`check_minimum_elements`], [`diff_sboms`], [`write()`]
//! and [`pretty`]. The modules stay public for advanced use and may change between
//! minor versions.
//!
//! ## What it does
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

#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "binary")]
#[cfg_attr(docsrs, doc(cfg(feature = "binary")))]
pub mod binary;
pub mod bundle;
pub mod cargo_src;
pub mod cc;
pub mod cdx;
pub mod check;
pub mod model;
pub mod provenance;
pub mod read;
#[cfg(feature = "sign")]
#[cfg_attr(docsrs, doc(cfg(feature = "sign")))]
pub mod sign;
pub mod spdx;
pub mod util;

pub use cargo_src::CargoOptions;
pub use check::{DiffReport, Element};
pub use model::{Component, Inventory};
pub use read::Doc;

use anyhow::Result;
use model::{Kind, Lang, Phase};
use std::path::{Path, PathBuf};

/// Everything [`generate`] needs. Every field is optional; build it with
/// [`GenerateOptions::cargo`] or [`GenerateOptions::cc`] and the `with_*` methods, or
/// with a struct literal ending in `..Default::default()` (fields may be added in
/// minor releases).
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

impl GenerateOptions {
    /// Scan the Cargo project at `manifest_path` (a `Cargo.toml`).
    pub fn cargo(manifest_path: impl Into<PathBuf>) -> Self {
        GenerateOptions {
            cargo: Some(CargoOptions::new(manifest_path)),
            use_dpkg: true,
            ..Default::default()
        }
    }

    /// Scan a C/C++ build from its `compile_commands.json`, rooted at `project_root`.
    pub fn cc(project_root: impl Into<PathBuf>, compile_commands: impl Into<PathBuf>) -> Self {
        GenerateOptions {
            project_root: Some(project_root.into()),
            compile_commands: Some(compile_commands.into()),
            use_dpkg: true,
            ..Default::default()
        }
    }

    /// Resolve Rust features and dependencies for this target triple.
    pub fn with_target(mut self, triple: impl Into<String>) -> Self {
        if let Some(c) = &mut self.cargo {
            c.target = Some(triple.into());
        }
        self
    }

    /// The built artifact to hash and inspect (needs the `binary` feature).
    pub fn with_binary(mut self, path: impl Into<PathBuf>) -> Self {
        self.binary = Some(path.into());
        self
    }

    /// Verbose build log (make VERBOSE=1, ninja -v) for link and archive lines.
    pub fn with_build_log(mut self, path: impl Into<PathBuf>) -> Self {
        self.build_log = Some(path.into());
        self
    }

    /// A GNU ld / lld linker map; may be called more than once.
    pub fn with_link_map(mut self, path: impl Into<PathBuf>) -> Self {
        self.link_maps.push(path.into());
        self
    }

    /// The organization producing the SBOM (CISA 2026 "SBOM Author").
    pub fn with_author(mut self, author: impl Into<String>) -> Self {
        self.author = Some(author.into());
        self
    }

    /// The product's producer (CISA 2026 "Component Producer").
    pub fn with_producer(mut self, producer: impl Into<String>) -> Self {
        self.producer = Some(producer.into());
        self
    }

    /// Product name and version (default: package name and version, or git describe).
    pub fn with_product(mut self, name: impl Into<String>, version: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self.version = Some(version.into());
        self
    }

    /// Fixed SBOM timestamp as Unix seconds, for reproducible output
    /// (default: `SOURCE_DATE_EPOCH`, else now).
    pub fn with_timestamp(mut self, unix_secs: i64) -> Self {
        self.timestamp = Some(unix_secs);
        self
    }
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
    #[cfg(not(feature = "binary"))]
    if o.binary.is_some() {
        anyhow::bail!("reading a built artifact needs the `binary` feature of sbom-attest");
    }
    #[cfg(feature = "binary")]
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

/// The inventory as a CycloneDX 1.6 JSON document.
pub fn to_cyclonedx(inv: &Inventory) -> serde_json::Value {
    cdx::document(inv)
}

/// The inventory as an SPDX 2.3 JSON document. `namespace_base` is the URI the
/// `documentNamespace` starts with, e.g. `https://spdx.org/spdxdocs`.
pub fn to_spdx(inv: &Inventory, namespace_base: &str) -> serde_json::Value {
    spdx::document(inv, namespace_base)
}

/// Read a CycloneDX or SPDX JSON file (any producer) into a format-neutral [`Doc`],
/// returning the raw JSON as well.
pub fn load_sbom(path: impl AsRef<Path>) -> Result<(Doc, serde_json::Value)> {
    read::load(path.as_ref())
}

/// Score a document against the CISA 2026 SBOM minimum elements. Pass
/// `detached_signature = true` when a detached signature over the file verified.
/// [`check::score`] turns the result into 0-100.
pub fn check_minimum_elements(doc: &Doc, detached_signature: bool) -> Vec<Element> {
    check::minimum_elements(doc, detached_signature)
}

/// Compare a vendor SBOM with an independently generated one: undeclared,
/// unverified and version- or hash-mismatched components.
pub fn diff_sboms(vendor: &Doc, independent: &Doc) -> DiffReport {
    check::diff(vendor, independent)
}

/// Write `data` to `path`, creating parent directories.
pub fn write(path: impl AsRef<Path>, data: &[u8]) -> Result<()> {
    let path = path.as_ref();
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
