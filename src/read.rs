//! Read any CycloneDX (1.2 to 1.7) or SPDX 2.x JSON SBOM into one shape, for the diff
//! and the minimum-elements check. Vendor SBOMs come from other tools, so every field
//! is optional here.

use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Clone, Debug, Default)]
pub struct DocComponent {
    pub reference: String,
    pub name: String,
    pub group: Option<String>,
    pub version: Option<String>,
    pub purl: Option<String>,
    /// CPE 2.3 (or 2.2) name, when the document gives one.
    pub cpe: Option<String>,
    /// IANA-style algorithm name -> lowercase hex
    pub hashes: BTreeMap<String, String>,
    pub license: Option<String>,
    pub producer: Option<String>,
    pub identifiers: usize,
    pub build_only: bool,
}

#[derive(Clone, Debug, Default)]
pub struct Doc {
    pub format: String,
    pub format_version: String,
    pub author: Option<String>,
    pub signed: bool,
    pub tool_name: Option<String>,
    pub tool_version: Option<String>,
    pub timestamp: Option<String>,
    pub doc_version: Option<String>,
    pub generation_context: Vec<String>,
    pub root: Option<DocComponent>,
    pub components: Vec<DocComponent>,
    pub dependency_edges: usize,
    /// refs that appear in the dependency graph
    pub graph_refs: usize,
}

fn norm_alg(a: &str) -> String {
    match a.to_ascii_uppercase().replace('_', "-").as_str() {
        "SHA1" | "SHA-1" => "SHA-1".into(),
        "SHA256" | "SHA-256" => "SHA-256".into(),
        "SHA384" | "SHA-384" => "SHA-384".into(),
        "SHA512" | "SHA-512" => "SHA-512".into(),
        "MD5" => "MD5".into(),
        "SHA3-256" => "SHA3-256".into(),
        "SHA3-512" => "SHA3-512".into(),
        "BLAKE2B-256" => "BLAKE2b-256".into(),
        "BLAKE3" => "BLAKE3".into(),
        other => other.to_string(),
    }
}

fn s(v: &Value) -> Option<String> {
    v.as_str().map(String::from).filter(|x| !x.is_empty())
}

fn cdx_component(v: &Value, out: &mut Vec<DocComponent>) {
    let mut c = DocComponent {
        reference: s(&v["bom-ref"]).unwrap_or_default(),
        name: s(&v["name"]).unwrap_or_default(),
        group: s(&v["group"]),
        version: s(&v["version"]),
        purl: s(&v["purl"]),
        cpe: s(&v["cpe"]),
        ..Default::default()
    };
    for h in v["hashes"].as_array().into_iter().flatten() {
        if let (Some(a), Some(x)) = (s(&h["alg"]), s(&h["content"])) {
            c.hashes.insert(norm_alg(&a), x.to_lowercase());
        }
    }
    let lic: Vec<String> = v["licenses"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|l| {
            s(&l["expression"])
                .or_else(|| s(&l["license"]["id"]))
                .or_else(|| s(&l["license"]["name"]))
        })
        .collect();
    if !lic.is_empty() {
        c.license = Some(lic.join(" AND "));
    }
    c.producer = s(&v["supplier"]["name"])
        .or_else(|| s(&v["manufacturer"]["name"]))
        .or_else(|| s(&v["author"]))
        .or_else(|| {
            v["authors"]
                .as_array()
                .and_then(|a| a.first())
                .and_then(|a| s(&a["name"]))
        })
        .or_else(|| s(&v["publisher"]));
    c.identifiers = [
        &v["purl"],
        &v["cpe"],
        &v["swid"],
        &v["omniborId"],
        &v["swhid"],
    ]
    .iter()
    .filter(|x| !x.is_null())
    .count();
    c.build_only = v["scope"] == "excluded";
    let nested = v["components"].clone();
    out.push(c);
    for n in nested.as_array().into_iter().flatten() {
        cdx_component(n, out);
    }
}

pub fn from_cyclonedx(v: &Value) -> Doc {
    let mut d = Doc {
        format: "CycloneDX".into(),
        format_version: s(&v["specVersion"]).unwrap_or_default(),
        signed: v.get("signature").is_some_and(|x| !x.is_null()),
        doc_version: v["version"].as_i64().map(|x| x.to_string()),
        timestamp: s(&v["metadata"]["timestamp"]),
        ..Default::default()
    };
    let m = &v["metadata"];
    d.author = m["authors"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(|a| s(&a["name"]).or_else(|| s(&a["email"])))
        .or_else(|| s(&m["manufacture"]["name"]))
        .or_else(|| s(&m["manufacturer"]["name"]))
        .or_else(|| s(&m["supplier"]["name"]));
    // tools: legacy array, or the 1.5+ object
    let tool = match &m["tools"] {
        Value::Array(a) => a.first().map(|t| (s(&t["name"]), s(&t["version"]))),
        Value::Object(o) => o
            .get("components")
            .and_then(|c| c.as_array())
            .and_then(|a| a.first())
            .or_else(|| {
                o.get("services")
                    .and_then(|c| c.as_array())
                    .and_then(|a| a.first())
            })
            .map(|t| (s(&t["name"]), s(&t["version"]))),
        _ => None,
    };
    if let Some((n, ver)) = tool {
        d.tool_name = n;
        d.tool_version = ver;
    }
    d.generation_context = m["lifecycles"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|l| s(&l["phase"]).or_else(|| s(&l["name"])))
        .collect();
    if m["component"].is_object() {
        let mut r = Vec::new();
        cdx_component(&m["component"], &mut r);
        let mut it = r.into_iter();
        d.root = it.next();
        // components nested under the root (e.g. bin targets) are not dependencies
    }
    for c in v["components"].as_array().into_iter().flatten() {
        cdx_component(c, &mut d.components);
    }
    for dep in v["dependencies"].as_array().into_iter().flatten() {
        d.graph_refs += 1;
        d.dependency_edges += dep["dependsOn"].as_array().map(|a| a.len()).unwrap_or(0);
    }
    d
}

pub fn from_spdx(v: &Value) -> Doc {
    let ci = &v["creationInfo"];
    let creators: Vec<String> = ci["creators"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(s)
        .collect();
    let tool = creators
        .iter()
        .find_map(|c| c.strip_prefix("Tool:").map(|t| t.trim().to_string()));
    let (tool_name, tool_version) = match &tool {
        Some(t) => match t.rfind('-') {
            Some(i)
                if t[i + 1..]
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_digit()) =>
            {
                (Some(t[..i].to_string()), Some(t[i + 1..].to_string()))
            }
            _ => (Some(t.clone()), None),
        },
        None => (None, None),
    };
    let author = creators.iter().find_map(|c| {
        c.strip_prefix("Organization:")
            .or_else(|| c.strip_prefix("Person:"))
            .map(|x| x.trim().to_string())
    });
    let described: Vec<String> = v["relationships"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|r| {
            r["spdxElementId"] == "SPDXRef-DOCUMENT" && r["relationshipType"] == "DESCRIBES"
        })
        .filter_map(|r| s(&r["relatedSpdxElement"]))
        .chain(
            v["documentDescribes"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(s),
        )
        .collect();
    let mut d = Doc {
        format: "SPDX".into(),
        format_version: s(&v["spdxVersion"])
            .unwrap_or_default()
            .trim_start_matches("SPDX-")
            .to_string(),
        author,
        tool_name,
        tool_version,
        timestamp: s(&ci["created"]),
        doc_version: None,
        generation_context: s(&ci["comment"])
            .filter(|c| {
                c.to_lowercase().contains("build") || c.to_lowercase().contains("lifecycle")
            })
            .into_iter()
            .collect(),
        ..Default::default()
    };
    let mut build_only = std::collections::BTreeSet::new();
    for r in v["relationships"].as_array().into_iter().flatten() {
        let t = r["relationshipType"].as_str().unwrap_or("");
        if matches!(
            t,
            "DEPENDS_ON"
                | "CONTAINS"
                | "DEPENDENCY_OF"
                | "BUILD_DEPENDENCY_OF"
                | "DEV_DEPENDENCY_OF"
                | "STATIC_LINK"
                | "DYNAMIC_LINK"
        ) {
            d.dependency_edges += 1;
        }
        if t == "BUILD_DEPENDENCY_OF" {
            if let Some(x) = s(&r["spdxElementId"]) {
                build_only.insert(x);
            }
        }
    }
    for p in v["packages"].as_array().into_iter().flatten() {
        let mut c = DocComponent {
            reference: s(&p["SPDXID"]).unwrap_or_default(),
            name: s(&p["name"]).unwrap_or_default(),
            version: s(&p["versionInfo"]),
            ..Default::default()
        };
        for r in p["externalRefs"].as_array().into_iter().flatten() {
            let t = r["referenceType"].as_str().unwrap_or("");
            if t == "purl" {
                c.purl = s(&r["referenceLocator"]);
            } else if t.starts_with("cpe") {
                c.cpe = s(&r["referenceLocator"]);
            }
            c.identifiers += 1;
        }
        for h in p["checksums"].as_array().into_iter().flatten() {
            if let (Some(a), Some(x)) = (s(&h["algorithm"]), s(&h["checksumValue"])) {
                c.hashes.insert(norm_alg(&a), x.to_lowercase());
            }
        }
        c.license = s(&p["licenseDeclared"])
            .or_else(|| s(&p["licenseConcluded"]))
            .filter(|l| l != "NOASSERTION" && l != "NONE");
        c.producer = s(&p["supplier"])
            .or_else(|| s(&p["originator"]))
            .filter(|x| x != "NOASSERTION")
            .map(|x| {
                x.trim_start_matches("Organization:")
                    .trim_start_matches("Person:")
                    .trim()
                    .to_string()
            });
        c.build_only = build_only.contains(&c.reference);
        if described.contains(&c.reference) && d.root.is_none() {
            d.root = Some(c);
        } else {
            d.components.push(c);
        }
    }
    d.signed = false;
    d
}

pub fn load(path: &Path) -> Result<(Doc, Value)> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let v: Value =
        serde_json::from_str(&text).with_context(|| format!("{} is not JSON", path.display()))?;
    let doc = if v["bomFormat"] == "CycloneDX" {
        from_cyclonedx(&v)
    } else if v["spdxVersion"].is_string() {
        from_spdx(&v)
    } else {
        bail!("{} is neither CycloneDX nor SPDX JSON", path.display())
    };
    Ok((doc, v))
}
