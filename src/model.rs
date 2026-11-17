//! The format-neutral inventory that every input feeds and every writer reads.

use std::collections::{BTreeMap, BTreeSet};

/// What a component is, in CycloneDX terms.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    Application,
    Library,
    Firmware,
    File,
}

impl Kind {
    pub fn cdx(self) -> &'static str {
        match self {
            Kind::Application => "application",
            Kind::Library => "library",
            Kind::Firmware => "firmware",
            Kind::File => "file",
        }
    }
    pub fn spdx_purpose(self) -> &'static str {
        match self {
            Kind::Application => "APPLICATION",
            Kind::Library => "LIBRARY",
            Kind::Firmware => "FIRMWARE",
            Kind::File => "FILE",
        }
    }
}

/// Whether the component ends up in the shipped artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Scope {
    /// Linked or compiled into the artifact.
    Required,
    /// Used only to build it (build scripts, proc macros, build-only libraries).
    Excluded,
}

/// Source language, used for the optional memory-safety property.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Lang {
    Rust,
    C,
    Cpp,
    Asm,
    Unknown,
}

impl Lang {
    pub fn as_str(self) -> &'static str {
        match self {
            Lang::Rust => "rust",
            Lang::C => "c",
            Lang::Cpp => "c++",
            Lang::Asm => "asm",
            Lang::Unknown => "unknown",
        }
    }
}

/// One software component.
#[derive(Clone, Debug)]
pub struct Component {
    /// Stable identifier, used as the CycloneDX bom-ref and the SPDX id seed.
    pub id: String,
    pub kind: Kind,
    pub name: String,
    pub version: Option<String>,
    pub purl: Option<String>,
    /// (IANA hash name such as "SHA-256", lowercase hex)
    pub hashes: Vec<(String, String)>,
    /// What the hash was computed over ("crate-archive", "binary", "archive", "source-files").
    pub hash_subject: Option<String>,
    /// SPDX license expression as declared by the producer.
    pub license: Option<String>,
    /// Component producer (CISA 2026), e.g. crate authors or the Debian maintainer.
    pub producer: Option<String>,
    pub description: Option<String>,
    pub scope: Scope,
    pub lang: Lang,
    /// Which inputs saw this component ("cargo-tree", "compile_commands", "linker-map", ...).
    pub evidence: BTreeSet<String>,
    pub properties: BTreeMap<String, String>,
    /// (CycloneDX external reference type, url)
    pub external_refs: Vec<(String, String)>,
}

impl Component {
    pub fn new(id: impl Into<String>, kind: Kind, name: impl Into<String>) -> Self {
        Component {
            id: id.into(),
            kind,
            name: name.into(),
            version: None,
            purl: None,
            hashes: Vec::new(),
            hash_subject: None,
            license: None,
            producer: None,
            description: None,
            scope: Scope::Required,
            lang: Lang::Unknown,
            evidence: BTreeSet::new(),
            properties: BTreeMap::new(),
            external_refs: Vec::new(),
        }
    }

    pub fn sha256(&self) -> Option<&str> {
        self.hashes
            .iter()
            .find(|(a, _)| a == "SHA-256")
            .map(|(_, v)| v.as_str())
    }

    /// Merge what another input learned about the same component.
    pub fn absorb(&mut self, other: Component) {
        if self.version.is_none() {
            self.version = other.version;
        }
        if self.purl.is_none() {
            self.purl = other.purl;
        }
        for h in other.hashes {
            if !self.hashes.iter().any(|(a, _)| *a == h.0) {
                self.hashes.push(h);
            }
        }
        if self.hash_subject.is_none() {
            self.hash_subject = other.hash_subject;
        }
        if self.license.is_none() {
            self.license = other.license;
        }
        if self.producer.is_none() {
            self.producer = other.producer;
        }
        if self.description.is_none() {
            self.description = other.description;
        }
        if other.scope == Scope::Required {
            self.scope = Scope::Required;
        }
        if self.lang == Lang::Unknown {
            self.lang = other.lang;
        }
        self.evidence.extend(other.evidence);
        for (k, v) in other.properties {
            self.properties.entry(k).or_insert(v);
        }
        for r in other.external_refs {
            if !self.external_refs.contains(&r) {
                self.external_refs.push(r);
            }
        }
    }
}

/// CISA 2026 "SBOM Generation Context": where in the lifecycle the data came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase {
    /// Source and manifests, before compiling ("before build").
    PreBuild,
    /// Compiler and linker invocations of an actual build ("build").
    Build,
    /// Analysis of the finished binary ("after build").
    PostBuild,
}

impl Phase {
    pub fn cdx(self) -> &'static str {
        match self {
            Phase::PreBuild => "pre-build",
            Phase::Build => "build",
            Phase::PostBuild => "post-build",
        }
    }
}

/// The whole inventory for one target artifact.
#[derive(Clone, Debug)]
pub struct Inventory {
    pub root: Component,
    pub components: BTreeMap<String, Component>,
    /// bom-ref -> bom-refs it depends on
    pub deps: BTreeMap<String, BTreeSet<String>>,
    pub phases: BTreeSet<Phase>,
    /// RFC 3339 UTC timestamp
    pub timestamp: String,
    /// SBOM author (CISA 2026): the entity operating the tool.
    pub author: Option<String>,
    /// Free-form notes about what could not be determined ("known unknowns").
    pub unknowns: Vec<String>,
    /// Target triple, when the build is for one.
    pub target: Option<String>,
    /// Extra document-level properties.
    pub properties: BTreeMap<String, String>,
}

impl Inventory {
    pub fn new(root: Component, timestamp: String) -> Self {
        Inventory {
            root,
            components: BTreeMap::new(),
            deps: BTreeMap::new(),
            phases: BTreeSet::new(),
            timestamp,
            author: None,
            unknowns: Vec::new(),
            target: None,
            properties: BTreeMap::new(),
        }
    }

    /// Add a component, merging with an existing one that has the same id.
    pub fn add(&mut self, c: Component) {
        if c.id == self.root.id {
            self.root.absorb(c);
            return;
        }
        match self.components.get_mut(&c.id) {
            Some(existing) => existing.absorb(c),
            None => {
                self.components.insert(c.id.clone(), c);
            }
        }
    }

    pub fn depend(&mut self, from: &str, to: &str) {
        if from == to {
            return;
        }
        self.deps
            .entry(from.to_string())
            .or_default()
            .insert(to.to_string());
    }

    pub fn get(&self, id: &str) -> Option<&Component> {
        if id == self.root.id {
            Some(&self.root)
        } else {
            self.components.get(id)
        }
    }

    /// Components with no SHA-256, i.e. the hash value is unknown to the author.
    pub fn unhashed(&self) -> Vec<&Component> {
        self.components
            .values()
            .filter(|c| c.hashes.is_empty())
            .collect()
    }

    /// Apply the memory-safe-language property to every component.
    pub fn mark_memsafe(&mut self) {
        let apply = |c: &mut Component| {
            let value = match c.lang {
                Lang::Rust => {
                    if c.properties.contains_key("sbom-attest:cargo:links")
                        || c.name.ends_with("-sys")
                    {
                        "rust-ffi"
                    } else {
                        "true"
                    }
                }
                Lang::C | Lang::Cpp | Lang::Asm => "false",
                Lang::Unknown => "unknown",
            };
            c.properties
                .insert("sbom-attest:memsafe".into(), value.into());
            c.properties
                .insert("sbom-attest:language".into(), c.lang.as_str().into());
        };
        apply(&mut self.root);
        for c in self.components.values_mut() {
            apply(c);
        }
    }
}
