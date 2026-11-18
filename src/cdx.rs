//! CycloneDX 1.6 JSON writer.

use crate::model::{Component, Inventory, Scope};
use crate::util::uuid_from;
use serde_json::{json, Map, Value};

pub const TOOL_NAME: &str = "sbom-attest";
pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const TOOL_REPO: &str = "https://github.com/Mattbusel/sbom-attest";

fn technique(evidence: &str) -> (&'static str, f64) {
    match evidence {
        "cargo-metadata" | "cargo-tree" | "dpkg" => ("manifest-analysis", 1.0),
        "cargo-auditable" | "binary" | "binary:needed" | "linker-map" => ("binary-analysis", 1.0),
        "compile_commands" | "depfile" | "build-log" => ("instrumentation", 0.9),
        _ => ("other", 0.5),
    }
}

fn properties(map: &std::collections::BTreeMap<String, String>) -> Value {
    Value::Array(
        map.iter()
            .map(|(k, v)| json!({"name": k, "value": v}))
            .collect(),
    )
}

pub fn license_json(expr: &str) -> Value {
    // these are the licenses the producer declared; sbom-attest does not conclude licenses
    if crate::util::spdx_expression_known(expr) {
        json!([{ "expression": expr, "acknowledgement": "declared" }])
    } else {
        json!([{ "license": { "name": expr, "acknowledgement": "declared" } }])
    }
}

pub fn component(c: &Component) -> Value {
    let mut m = Map::new();
    m.insert("type".into(), json!(c.kind.cdx()));
    m.insert("bom-ref".into(), json!(c.id));
    m.insert("name".into(), json!(c.name));
    if let Some(v) = &c.version {
        m.insert("version".into(), json!(v));
    }
    if let Some(p) = &c.producer {
        // CISA 2026 "Component Producer": the authors who created the component
        m.insert(
            "authors".into(),
            Value::Array(
                p.split(", ")
                    .filter(|a| !a.is_empty())
                    .map(|a| json!({ "name": a }))
                    .collect(),
            ),
        );
        m.insert("supplier".into(), json!({ "name": p }));
    }
    if let Some(d) = &c.description {
        m.insert("description".into(), json!(d));
    }
    m.insert(
        "scope".into(),
        json!(match c.scope {
            Scope::Required => "required",
            Scope::Excluded => "excluded",
        }),
    );
    if !c.hashes.is_empty() {
        let mut hs = c.hashes.clone();
        hs.sort();
        m.insert(
            "hashes".into(),
            Value::Array(
                hs.iter()
                    .map(|(a, v)| json!({"alg": a, "content": v}))
                    .collect(),
            ),
        );
    }
    if let Some(l) = &c.license {
        m.insert("licenses".into(), license_json(l));
    }
    if let Some(p) = &c.purl {
        m.insert("purl".into(), json!(p));
    }
    if !c.external_refs.is_empty() {
        let mut refs = c.external_refs.clone();
        refs.sort();
        refs.dedup();
        m.insert(
            "externalReferences".into(),
            Value::Array(
                refs.iter()
                    .map(|(t, u)| json!({"type": t, "url": u}))
                    .collect(),
            ),
        );
    }
    let mut props = c.properties.clone();
    if !c.evidence.is_empty() {
        props.insert(
            "sbom-attest:evidence".into(),
            c.evidence.iter().cloned().collect::<Vec<_>>().join(","),
        );
    }
    match &c.hash_subject {
        Some(s) => {
            props.insert("sbom-attest:hash-subject".into(), s.clone());
        }
        None => {
            // CISA 2026: say so when the hash value is unknown
            props.insert("sbom-attest:hash".into(), "unknown".into());
        }
    }
    if !props.is_empty() {
        m.insert("properties".into(), properties(&props));
    }
    if !c.evidence.is_empty() {
        let field = if c.purl.is_some() { "purl" } else { "name" };
        let mut methods: Vec<(&str, f64)> = c.evidence.iter().map(|e| technique(e)).collect();
        methods.sort_by(|a, b| a.0.cmp(b.0));
        methods.dedup_by(|a, b| a.0 == b.0);
        m.insert(
            "evidence".into(),
            json!({ "identity": [{
                "field": field,
                "confidence": methods.iter().map(|m| m.1).fold(0.0, f64::max),
                "methods": methods.iter().map(|(t, c)| json!({"technique": t, "confidence": c})).collect::<Vec<_>>(),
            }]}),
        );
    }
    Value::Object(m)
}

/// Build the CycloneDX 1.6 document (unsigned).
pub fn document(inv: &Inventory) -> Value {
    let components: Vec<Value> = inv.components.values().map(component).collect();
    let mut deps: Vec<Value> = Vec::new();
    let mut all_refs: Vec<&String> = std::iter::once(&inv.root.id)
        .chain(inv.components.keys())
        .collect();
    all_refs.sort();
    for r in all_refs {
        let on: Vec<&String> = inv
            .deps
            .get(r)
            .map(|s| s.iter().filter(|x| inv.get(x).is_some()).collect())
            .unwrap_or_default();
        deps.push(json!({"ref": r, "dependsOn": on}));
    }
    let mut meta = Map::new();
    meta.insert("timestamp".into(), json!(inv.timestamp));
    meta.insert(
        "lifecycles".into(),
        Value::Array(
            inv.phases
                .iter()
                .map(|p| json!({"phase": p.cdx()}))
                .collect(),
        ),
    );
    meta.insert(
        "tools".into(),
        json!({ "components": [{
            "type": "application",
            "name": TOOL_NAME,
            "version": TOOL_VERSION,
            "supplier": {"name": "Tensorust LLC"},
            "externalReferences": [{"type": "vcs", "url": TOOL_REPO}],
        }]}),
    );
    if let Some(a) = &inv.author {
        meta.insert("authors".into(), json!([{ "name": a }]));
    }
    if let Some(s) = inv.root.producer.as_ref().or(inv.author.as_ref()) {
        meta.insert("supplier".into(), json!({ "name": s }));
    }
    // the license of the SBOM data itself
    meta.insert(
        "licenses".into(),
        json!([{ "license": { "id": "CC0-1.0" } }]),
    );
    meta.insert("component".into(), component(&inv.root));
    let mut props = inv.properties.clone();
    if let Some(t) = &inv.target {
        props.insert("sbom-attest:target".into(), t.clone());
    }
    for (i, u) in inv.unknowns.iter().enumerate() {
        props.insert(format!("sbom-attest:unknown:{i:03}"), u.clone());
    }
    if !props.is_empty() {
        meta.insert("properties".into(), properties(&props));
    }

    let mut doc = json!({
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": Value::Object(meta),
        "components": components,
        "dependencies": deps,
        "compositions": [{
            "aggregate": if inv.unknowns.is_empty() && inv.unhashed().is_empty() { "complete" } else { "incomplete" },
            "assemblies": [inv.root.id],
            "dependencies": [inv.root.id],
        }],
    });
    // the serial number is derived from the content, so identical builds get identical SBOMs
    let seed = crate::util::canonical(&doc);
    doc["serialNumber"] = json!(format!("urn:uuid:{}", uuid_from(&seed)));
    doc
}
