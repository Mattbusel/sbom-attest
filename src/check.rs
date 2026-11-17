//! CISA 2026 SBOM minimum elements check, and the vendor-vs-independent SBOM diff
//! (the SWFT pattern: compare what the supplier declared against an SBOM built
//! independently from the same source or binary).

use crate::read::{Doc, DocComponent};
use serde_json::{json, Value};
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub struct Element {
    pub name: &'static str,
    pub level: &'static str,
    /// fraction of items that have it (1.0 for a present document field)
    pub coverage: f64,
    pub note: String,
}

/// Score a document against the CISA 2026 minimum elements data fields.
/// `detached_signature` is true when a verified detached signature accompanies it.
pub fn minimum_elements(doc: &Doc, detached_signature: bool) -> Vec<Element> {
    let mut out = Vec::new();
    let mut d = |name, ok: bool, note: String| {
        out.push(Element {
            name,
            level: "document",
            coverage: if ok { 1.0 } else { 0.0 },
            note,
        })
    };
    d(
        "SBOM Author",
        doc.author.is_some(),
        doc.author.clone().unwrap_or_default(),
    );
    d(
        "SBOM Author Signature",
        doc.signed || detached_signature,
        if doc.signed {
            "embedded".into()
        } else if detached_signature {
            "detached, verified".into()
        } else {
            String::new()
        },
    );
    d(
        "SBOM Data Format Name",
        !doc.format.is_empty(),
        doc.format.clone(),
    );
    d(
        "SBOM Data Format Version",
        !doc.format_version.is_empty(),
        doc.format_version.clone(),
    );
    d(
        "SBOM Generation Context",
        !doc.generation_context.is_empty(),
        doc.generation_context.join(","),
    );
    d(
        "SBOM Timestamp",
        doc.timestamp.is_some(),
        doc.timestamp.clone().unwrap_or_default(),
    );
    d(
        "SBOM Tool Name",
        doc.tool_name.is_some(),
        doc.tool_name.clone().unwrap_or_default(),
    );
    d(
        "SBOM Tool Version",
        doc.tool_version.is_some(),
        doc.tool_version.clone().unwrap_or_default(),
    );
    d(
        "SBOM Version",
        doc.doc_version.is_some() || doc.format == "SPDX",
        doc.doc_version
            .clone()
            .unwrap_or_else(|| "SPDX documentNamespace".into()),
    );

    let comps: Vec<&DocComponent> = doc.root.iter().chain(doc.components.iter()).collect();
    let n = comps.len().max(1) as f64;
    let mut c = |name, f: &dyn Fn(&DocComponent) -> bool| {
        let k = comps.iter().filter(|c| f(c)).count();
        out.push(Element {
            name,
            level: "component",
            coverage: k as f64 / n,
            note: format!("{k}/{}", comps.len()),
        });
    };
    c("Component Name", &|c| !c.name.is_empty());
    c("Component Version", &|c| c.version.is_some());
    c("Component Producer", &|c| c.producer.is_some());
    c("Component Identifiers", &|c| {
        c.purl.is_some() || c.identifiers > 0
    });
    c("Component Hash Value", &|c| !c.hashes.is_empty());
    c("Component Hash Algorithm", &|c| !c.hashes.is_empty());
    c("Component License", &|c| c.license.is_some());
    out.push(Element {
        name: "Component Dependency Relationship",
        level: "document",
        coverage: if doc.dependency_edges > 0 || comps.len() <= 1 {
            1.0
        } else {
            0.0
        },
        note: format!("{} edges", doc.dependency_edges),
    });
    out
}

/// Overall score 0..100: the mean coverage of all elements.
pub fn score(elements: &[Element]) -> f64 {
    if elements.is_empty() {
        return 0.0;
    }
    100.0 * elements.iter().map(|e| e.coverage).sum::<f64>() / elements.len() as f64
}

pub fn elements_json(elements: &[Element]) -> Value {
    json!({
        "framework": "CISA 2026 Minimum Elements for a Software Bill of Materials",
        "score": (score(elements) * 10.0).round() / 10.0,
        "elements": elements.iter().map(|e| json!({
            "element": e.name, "level": e.level,
            "coverage": (e.coverage * 1000.0).round() / 1000.0, "detail": e.note,
        })).collect::<Vec<_>>(),
    })
}

pub fn elements_markdown(elements: &[Element]) -> String {
    let mut s = String::from("| Element | Level | Coverage | Detail |\n|---|---|---|---|\n");
    for e in elements {
        s.push_str(&format!(
            "| {} | {} | {:.0}% | {} |\n",
            e.name,
            e.level,
            e.coverage * 100.0,
            e.note.replace('|', "/")
        ));
    }
    s.push_str(&format!("\nScore: {:.1} / 100\n", score(elements)));
    s
}

/// The matching key: purl type/namespace/name without version or qualifiers, else the
/// normalised name.
pub fn match_key(c: &DocComponent) -> String {
    if let Some(p) = &c.purl {
        let p = p.split(['?', '#']).next().unwrap_or(p);
        let p = match p.rfind('@') {
            Some(i) if i > p.find('/').unwrap_or(0) => &p[..i],
            _ => p,
        };
        return p.to_lowercase().replace('_', "-");
    }
    let name = match &c.group {
        Some(g) => format!("{g}/{}", c.name),
        None => c.name.clone(),
    };
    format!("name:{}", name.to_lowercase().replace('_', "-"))
}

#[derive(Debug, Default)]
pub struct DiffReport {
    pub matched: usize,
    /// built independently but not declared by the vendor (runtime)
    pub undeclared: Vec<DocComponent>,
    /// built independently, build-only, not declared by the vendor
    pub undeclared_build_only: Vec<DocComponent>,
    /// declared by the vendor but not found independently
    pub unverified: Vec<DocComponent>,
    /// (key, vendor version, independent version)
    pub version_mismatch: Vec<(String, String, String)>,
    /// (key, algorithm, vendor value, independent value)
    pub hash_mismatch: Vec<(String, String, String, String)>,
}

fn index(doc: &Doc) -> BTreeMap<String, Vec<DocComponent>> {
    let mut m: BTreeMap<String, Vec<DocComponent>> = BTreeMap::new();
    for c in &doc.components {
        m.entry(match_key(c)).or_default().push(c.clone());
    }
    m
}

pub fn diff(vendor: &Doc, independent: &Doc) -> DiffReport {
    let v = index(vendor);
    let i = index(independent);
    let mut r = DiffReport::default();
    for (k, ics) in &i {
        match v.get(k) {
            None => {
                for c in ics {
                    if c.build_only {
                        r.undeclared_build_only.push(c.clone());
                    } else {
                        r.undeclared.push(c.clone());
                    }
                }
            }
            Some(vcs) => {
                for ic in ics {
                    let same_version = vcs.iter().find(|vc| vc.version == ic.version);
                    match same_version {
                        Some(vc) => {
                            r.matched += 1;
                            for (alg, ih) in &ic.hashes {
                                if let Some(vh) = vc.hashes.get(alg) {
                                    if vh != ih {
                                        r.hash_mismatch.push((
                                            k.clone(),
                                            alg.clone(),
                                            vh.clone(),
                                            ih.clone(),
                                        ));
                                    }
                                }
                            }
                        }
                        None => r.version_mismatch.push((
                            k.clone(),
                            vcs.iter()
                                .filter_map(|c| c.version.clone())
                                .collect::<Vec<_>>()
                                .join(","),
                            ic.version.clone().unwrap_or_default(),
                        )),
                    }
                }
            }
        }
    }
    for (k, vcs) in &v {
        if !i.contains_key(k) {
            r.unverified.extend(vcs.iter().cloned());
        }
    }
    r
}

fn label(c: &DocComponent) -> String {
    format!(
        "{} {}{}",
        c.name,
        c.version.clone().unwrap_or_else(|| "(no version)".into()),
        c.purl
            .as_ref()
            .map(|p| format!(" `{p}`"))
            .unwrap_or_default()
    )
}

impl DiffReport {
    pub fn clean(&self) -> bool {
        self.undeclared.is_empty()
            && self.unverified.is_empty()
            && self.version_mismatch.is_empty()
            && self.hash_mismatch.is_empty()
    }

    pub fn to_json(&self) -> Value {
        let list = |v: &Vec<DocComponent>| -> Vec<Value> {
            v.iter()
                .map(|c| json!({"name": c.name, "version": c.version, "purl": c.purl}))
                .collect()
        };
        json!({
            "matched": self.matched,
            "undeclared": list(&self.undeclared),
            "undeclaredBuildOnly": list(&self.undeclared_build_only),
            "unverified": list(&self.unverified),
            "versionMismatch": self.version_mismatch.iter().map(|(k, a, b)| json!({"component": k, "vendor": a, "independent": b})).collect::<Vec<_>>(),
            "hashMismatch": self.hash_mismatch.iter().map(|(k, alg, a, b)| json!({"component": k, "alg": alg, "vendor": a, "independent": b})).collect::<Vec<_>>(),
        })
    }

    pub fn to_markdown(&self, vendor_name: &str, independent_name: &str) -> String {
        let mut s = format!(
            "# SBOM discrepancy report\n\nVendor SBOM: `{vendor_name}`\nIndependent SBOM: `{independent_name}`\n\n\
             | Finding | Count |\n|---|---|\n| Matched (same component and version) | {} |\n\
             | Undeclared: in the build, missing from the vendor SBOM | {} |\n\
             | Undeclared build-only components | {} |\n\
             | Unverified: declared by the vendor, not found in the build | {} |\n\
             | Version mismatches | {} |\n| Hash mismatches | {} |\n",
            self.matched,
            self.undeclared.len(),
            self.undeclared_build_only.len(),
            self.unverified.len(),
            self.version_mismatch.len(),
            self.hash_mismatch.len()
        );
        let mut section = |title: &str, items: Vec<String>| {
            if !items.is_empty() {
                s.push_str(&format!("\n## {title}\n\n"));
                for i in items {
                    s.push_str(&format!("- {i}\n"));
                }
            }
        };
        section(
            "Undeclared components",
            self.undeclared.iter().map(label).collect(),
        );
        section(
            "Unverified components",
            self.unverified.iter().map(label).collect(),
        );
        section(
            "Version mismatches",
            self.version_mismatch
                .iter()
                .map(|(k, a, b)| format!("`{k}`: vendor {a}, build {b}"))
                .collect(),
        );
        section(
            "Hash mismatches",
            self.hash_mismatch
                .iter()
                .map(|(k, alg, a, b)| format!("`{k}` {alg}: vendor {a}, build {b}"))
                .collect(),
        );
        section(
            "Undeclared build-only components",
            self.undeclared_build_only.iter().map(label).collect(),
        );
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn comp(name: &str, ver: &str, purl: Option<&str>, h: Option<&str>) -> DocComponent {
        let mut c = DocComponent {
            name: name.into(),
            version: Some(ver.into()),
            purl: purl.map(String::from),
            ..Default::default()
        };
        if let Some(h) = h {
            c.hashes.insert("SHA-256".into(), h.into());
        }
        c
    }

    #[test]
    fn keys_drop_version_and_qualifiers() {
        let c = comp(
            "a",
            "1",
            Some("pkg:cargo/Foo_bar@1.0.0?download_url=x"),
            None,
        );
        assert_eq!(match_key(&c), "pkg:cargo/foo-bar");
        let n = comp("zlib", "1", None, None);
        assert_eq!(match_key(&n), "name:zlib");
    }

    #[test]
    fn diff_finds_each_class() {
        let vendor = Doc {
            components: vec![
                comp("a", "1.0", Some("pkg:cargo/a@1.0"), Some("aa")),
                comp("b", "1.0", Some("pkg:cargo/b@1.0"), None),
                comp("gone", "1.0", Some("pkg:cargo/gone@1.0"), None),
                comp("h", "1.0", Some("pkg:cargo/h@1.0"), Some("11")),
            ],
            ..Default::default()
        };
        let mut build_only = comp("cc", "1.0", Some("pkg:cargo/cc@1.0"), None);
        build_only.build_only = true;
        let independent = Doc {
            components: vec![
                comp("a", "1.0", Some("pkg:cargo/a@1.0"), Some("aa")),
                comp("b", "2.0", Some("pkg:cargo/b@2.0"), None),
                comp("zlib", "1.3", None, None),
                comp("h", "1.0", Some("pkg:cargo/h@1.0"), Some("22")),
                build_only,
            ],
            ..Default::default()
        };
        let r = diff(&vendor, &independent);
        assert_eq!(r.matched, 2);
        assert_eq!(r.undeclared.len(), 1);
        assert_eq!(r.undeclared[0].name, "zlib");
        assert_eq!(r.undeclared_build_only.len(), 1);
        assert_eq!(r.unverified.len(), 1);
        assert_eq!(r.version_mismatch.len(), 1);
        assert_eq!(r.hash_mismatch.len(), 1);
        assert!(!r.clean());
        assert!(r.to_markdown("v", "i").contains("zlib 1.3"));
    }

    #[test]
    fn empty_doc_scores_low() {
        let e = minimum_elements(&Doc::default(), false);
        assert!(score(&e) < 30.0);
    }
}
