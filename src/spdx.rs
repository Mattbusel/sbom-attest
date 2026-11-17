//! SPDX 2.3 JSON writer.

use crate::cdx::{TOOL_NAME, TOOL_VERSION};
use crate::model::{Component, Inventory, Scope};
use crate::util::{id_safe, spdx_expression_known, uuid_from};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

fn spdx_alg(a: &str) -> Option<&'static str> {
    match a {
        "SHA-1" => Some("SHA1"),
        "SHA-256" => Some("SHA256"),
        "SHA-384" => Some("SHA384"),
        "SHA-512" => Some("SHA512"),
        _ => None,
    }
}

fn package(c: &Component, spdx_id: &str) -> Value {
    let mut m = Map::new();
    m.insert("SPDXID".into(), json!(spdx_id));
    m.insert("name".into(), json!(c.name));
    if let Some(v) = &c.version {
        m.insert("versionInfo".into(), json!(v));
    }
    m.insert(
        "supplier".into(),
        json!(match &c.producer {
            Some(p) => format!("Organization: {}", p.replace(['(', ')'], "")),
            None => "NOASSERTION".into(),
        }),
    );
    let download = c
        .external_refs
        .iter()
        .find(|(t, _)| t == "vcs")
        .map(|(_, u)| u.clone())
        .unwrap_or_else(|| "NOASSERTION".into());
    m.insert("downloadLocation".into(), json!(download));
    m.insert("filesAnalyzed".into(), json!(false));
    let checksums: Vec<Value> = {
        let mut hs = c.hashes.clone();
        hs.sort();
        hs.iter()
            .filter_map(|(a, v)| spdx_alg(a).map(|a| json!({"algorithm": a, "checksumValue": v})))
            .collect()
    };
    if !checksums.is_empty() {
        m.insert("checksums".into(), Value::Array(checksums));
    }
    let declared = match &c.license {
        Some(l) if spdx_expression_known(l) => l.clone(),
        _ => "NOASSERTION".into(),
    };
    m.insert("licenseConcluded".into(), json!("NOASSERTION"));
    m.insert("licenseDeclared".into(), json!(declared));
    m.insert("copyrightText".into(), json!("NOASSERTION"));
    if let Some(d) = &c.description {
        m.insert("description".into(), json!(d));
    }
    if let Some(h) = c.external_refs.iter().find(|(t, _)| t == "website") {
        m.insert("homepage".into(), json!(h.1));
    }
    m.insert("primaryPackagePurpose".into(), json!(c.kind.spdx_purpose()));
    if let Some(p) = &c.purl {
        m.insert(
            "externalRefs".into(),
            json!([{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": p,
            }]),
        );
    }
    let mut notes = Vec::new();
    if let Some(s) = &c.hash_subject {
        notes.push(format!("hash-subject={s}"));
    } else {
        notes.push("hash=unknown".into());
    }
    if c.scope == Scope::Excluded {
        notes.push("build-only".into());
    }
    if !c.evidence.is_empty() {
        notes.push(format!(
            "evidence={}",
            c.evidence.iter().cloned().collect::<Vec<_>>().join(",")
        ));
    }
    if let Some(v) = c.properties.get("sbom-attest:memsafe") {
        notes.push(format!("memsafe={v}"));
    }
    m.insert("comment".into(), json!(notes.join("; ")));
    Value::Object(m)
}

pub fn document(inv: &Inventory, namespace_base: &str) -> Value {
    // stable SPDX ids
    let mut ids: BTreeMap<&str, String> = BTreeMap::new();
    let root_spdx = format!("SPDXRef-Package-{}", id_safe(&inv.root.id));
    ids.insert(&inv.root.id, root_spdx.clone());
    let mut used = std::collections::BTreeSet::new();
    used.insert(root_spdx.clone());
    for c in inv.components.values() {
        let mut id = format!("SPDXRef-Package-{}", id_safe(&c.id));
        let mut n = 2;
        while used.contains(&id) {
            id = format!("SPDXRef-Package-{}-{n}", id_safe(&c.id));
            n += 1;
        }
        used.insert(id.clone());
        ids.insert(&c.id, id);
    }
    let mut packages = vec![package(&inv.root, &root_spdx)];
    packages.extend(
        inv.components
            .values()
            .map(|c| package(c, &ids[c.id.as_str()])),
    );

    let mut rels = vec![json!({
        "spdxElementId": "SPDXRef-DOCUMENT",
        "relationshipType": "DESCRIBES",
        "relatedSpdxElement": root_spdx,
    })];
    for (from, tos) in &inv.deps {
        let Some(f) = ids.get(from.as_str()) else {
            continue;
        };
        for to in tos {
            let Some(t) = ids.get(to.as_str()) else {
                continue;
            };
            let build_only = inv.get(to).is_some_and(|c| c.scope == Scope::Excluded);
            rels.push(json!({
                "spdxElementId": f,
                "relationshipType": if build_only { "BUILD_DEPENDENCY_OF" } else { "DEPENDS_ON" },
                "relatedSpdxElement": t,
            }));
        }
    }
    // BUILD_DEPENDENCY_OF points the other way round
    for r in rels.iter_mut() {
        if r["relationshipType"] == "BUILD_DEPENDENCY_OF" {
            let a = r["spdxElementId"].clone();
            r["spdxElementId"] = r["relatedSpdxElement"].clone();
            r["relatedSpdxElement"] = a;
        }
    }

    let mut creators = vec![format!("Tool: {TOOL_NAME}-{TOOL_VERSION}")];
    if let Some(a) = &inv.author {
        creators.push(format!("Organization: {a}"));
    }
    let phases: Vec<&str> = inv.phases.iter().map(|p| p.cdx()).collect();
    let mut doc = json!({
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": format!("{}-{}", inv.root.name, inv.root.version.clone().unwrap_or_default()),
        "creationInfo": {
            "created": inv.timestamp,
            "creators": creators,
            "comment": format!("Generation context (lifecycle phases): {}", phases.join(", ")),
        },
        "packages": packages,
        "relationships": rels,
    });
    let seed = crate::sign::canonical(&doc);
    doc["documentNamespace"] = json!(format!(
        "{}/{}-{}",
        namespace_base.trim_end_matches('/'),
        id_safe(&inv.root.name),
        uuid_from(&seed)
    ));
    doc
}
