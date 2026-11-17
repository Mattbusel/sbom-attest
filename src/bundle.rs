//! `--profile dowi-8430`: a release evidence bundle indexed to the paragraphs of
//! DoW Instruction 8430.01, "Accelerated Mission Software" (effective September 8, 2026)
//! that ask for machine-readable SBOM, provenance and assurance evidence.
//!
//! The index says which file in the bundle is offered as evidence for which paragraph.
//! It is not a compliance determination: per paragraph 3.5.a(2) the DoW CIO defines
//! the evidence formats, and the program's authorizing official decides.

use serde_json::{json, Value};

pub struct Paragraph {
    pub id: &'static str,
    pub title: &'static str,
    /// short quotation from the instruction
    pub text: &'static str,
    /// artifact roles that serve as evidence
    pub roles: &'static [&'static str],
}

pub const INSTRUCTION: &str =
    "DoW Instruction 8430.01, Accelerated Mission Software (effective September 8, 2026)";

pub const PARAGRAPHS: &[Paragraph] = &[
    Paragraph {
        id: "2.8.f",
        title: "Verifiable assurance evidence",
        text: "Produce verifiable assurance evidence, including static and dynamic code analysis, fuzz testing, penetration testing, and secure-code reviews",
        roles: &["sarif"],
    },
    Paragraph {
        id: "2.8.k",
        title: "Software supply chain risk management",
        text: "generating and maintaining software bills of materials (SBOMs) for custom software and capturing SBOMs for COTS software, tracking provenance and pedigree",
        roles: &["sbom-cyclonedx", "sbom-spdx", "vendor-sbom", "sbom-diff", "provenance"],
    },
    Paragraph {
        id: "3.5.a(1)",
        title: "Verifiable assurance as a condition for operation",
        text: "supported by machine-readable evidence of its component composition, build integrity, and application security",
        roles: &["sbom-cyclonedx", "provenance", "sarif"],
    },
    Paragraph {
        id: "3.5.b",
        title: "Software component transparency",
        text: "an accurate SBOM is generated and maintained for all covered software ... necessary for supply chain analysis, such as vulnerability and license management",
        roles: &["sbom-cyclonedx", "sbom-spdx", "min-elements", "sbom-diff"],
    },
    Paragraph {
        id: "3.5.c(1)",
        title: "Verifiable build integrity, provenance, and pedigree",
        text: "generate machine-readable provenance (a verifiable history of the software's origin and build process) and attestations that provide pedigree",
        roles: &["provenance", "sbom-attestation", "signature", "public-key"],
    },
    Paragraph {
        id: "3.5.c(2)",
        title: "Marking and personal information in evidence",
        text: "Evidence packages, SBOMs, provenance, and associated telemetry that contain sensitive information will be marked ... minimize collection of personally identifiable information",
        roles: &["index"],
    },
    Paragraph {
        id: "3.5.i(4)",
        title: "Third-party and transitive dependencies",
        text: "All third-party software components, including open-source software, COTS products, and their transitive dependencies, must be included in the SBOM",
        roles: &["sbom-cyclonedx", "sbom-diff"],
    },
    Paragraph {
        id: "3.6.f",
        title: "AI component transparency",
        text: "maintain a record of models, versions, and significant datasets used to generate or test software",
        roles: &["ai-record"],
    },
];

/// The four paragraphs this profile is built around; the others are indexed when
/// evidence for them is present.
pub const CORE: &[&str] = &["2.8.f", "2.8.k", "3.5.b", "3.5.c(1)"];

#[derive(Clone, Debug)]
pub struct Entry {
    pub path: String,
    pub sha256: String,
    pub role: String,
    pub note: String,
}

pub fn index(entries: &[Entry], marking: &str, root: &Value, extra: Value) -> Value {
    let mut paras = Vec::new();
    let mut gaps = Vec::new();
    for p in PARAGRAPHS {
        let files: Vec<&str> = entries
            .iter()
            .filter(|e| {
                p.roles.contains(&e.role.as_str()) || (p.id == "3.5.c(2)" && e.role == "index")
            })
            .map(|e| e.path.as_str())
            .collect();
        let status = if p.id == "3.5.c(2)" {
            "addressed by bundle design"
        } else if files.is_empty() {
            "no evidence supplied"
        } else {
            "evidence present"
        };
        if files.is_empty() && CORE.contains(&p.id) {
            gaps.push(format!("{}: {}", p.id, p.title));
        }
        let mut v = json!({
            "paragraph": p.id,
            "title": p.title,
            "quote": p.text,
            "status": status,
            "artifacts": files,
        });
        if p.id == "3.5.c(2)" {
            v["artifacts"] = json!(["index.json"]);
            v["note"] = json!(format!(
                "Marking: {marking}. Paths are written relative to the project root or with the home directory as ~; provenance carries no user or host names."
            ));
        }
        paras.push(v);
    }
    json!({
        "profile": "dowi-8430",
        "instruction": INSTRUCTION,
        "disclaimer": "This index maps bundle files to paragraphs of the instruction. It is not a compliance determination; evidence formats are defined by the DoW CIO (para 3.5.a(2)).",
        "marking": marking,
        "subject": root,
        "artifacts": entries.iter().map(|e| json!({"path": e.path, "sha256": e.sha256, "role": e.role, "note": e.note})).collect::<Vec<_>>(),
        "paragraphs": paras,
        "gaps": gaps,
        "details": extra,
    })
}

pub fn markdown(idx: &Value) -> String {
    let mut s = format!(
        "# Evidence bundle: {}\n\n**Marking:** {}\n\n**Instruction:** {}\n\n> {}\n\n## Subject\n\n- {} {}\n\n## Paragraph index\n\n| Paragraph | Title | Status | Evidence |\n|---|---|---|---|\n",
        idx["subject"]["name"].as_str().unwrap_or(""),
        idx["marking"].as_str().unwrap_or(""),
        idx["instruction"].as_str().unwrap_or(""),
        idx["disclaimer"].as_str().unwrap_or(""),
        idx["subject"]["name"].as_str().unwrap_or(""),
        idx["subject"]["version"].as_str().unwrap_or(""),
    );
    for p in idx["paragraphs"].as_array().into_iter().flatten() {
        let files: Vec<String> = p["artifacts"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|f| f.as_str().map(|f| format!("`{f}`")))
            .collect();
        s.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            p["paragraph"].as_str().unwrap_or(""),
            p["title"].as_str().unwrap_or(""),
            p["status"].as_str().unwrap_or(""),
            if files.is_empty() {
                "none".to_string()
            } else {
                files.join(", ")
            }
        ));
    }
    s.push_str("\n## Quoted requirements\n\n");
    for p in idx["paragraphs"].as_array().into_iter().flatten() {
        s.push_str(&format!(
            "- **{}**: \"{}\"\n",
            p["paragraph"].as_str().unwrap_or(""),
            p["quote"].as_str().unwrap_or("")
        ));
    }
    s.push_str("\n## Files\n\n| File | Role | SHA-256 | Note |\n|---|---|---|---|\n");
    for a in idx["artifacts"].as_array().into_iter().flatten() {
        s.push_str(&format!(
            "| `{}` | {} | `{}` | {} |\n",
            a["path"].as_str().unwrap_or(""),
            a["role"].as_str().unwrap_or(""),
            &a["sha256"].as_str().unwrap_or("")[..16.min(a["sha256"].as_str().unwrap_or("").len())],
            a["note"].as_str().unwrap_or("")
        ));
    }
    let gaps: Vec<&str> = idx["gaps"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|g| g.as_str())
        .collect();
    if !gaps.is_empty() {
        s.push_str("\n## Gaps\n\n");
        for g in gaps {
            s.push_str(&format!("- {g}\n"));
        }
    }
    s.push_str("\n## Verify\n\n```sh\nsha256sum -c SHA256SUMS\nsbom-attest verify-sbom --pub signing-key.pub sbom.cdx.json\ncosign verify-blob --key signing-key.pub --signature sbom.cdx.json.sig --insecure-ignore-tlog=true sbom.cdx.json\ncosign verify-blob-attestation --key signing-key.pub --signature provenance.intoto.json --type slsaprovenance1 --insecure-ignore-tlog=true <artifact>\n```\n");
    s
}

/// Light validation of a SARIF 2.1.0 file: returns (tool names, result count).
pub fn sarif_summary(v: &Value) -> Option<(Vec<String>, usize)> {
    if v["version"] != "2.1.0" {
        return None;
    }
    let runs = v["runs"].as_array()?;
    let tools = runs
        .iter()
        .filter_map(|r| r["tool"]["driver"]["name"].as_str().map(String::from))
        .collect();
    let results = runs
        .iter()
        .map(|r| r["results"].as_array().map(|a| a.len()).unwrap_or(0))
        .sum();
    Some((tools, results))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_reports_gaps() {
        let entries = vec![Entry {
            path: "sbom.cdx.json".into(),
            sha256: "00".into(),
            role: "sbom-cyclonedx".into(),
            note: String::new(),
        }];
        let idx = index(&entries, "UNCLASSIFIED", &json!({"name": "fw"}), json!({}));
        let gaps: Vec<String> = idx["gaps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|g| g.as_str().unwrap().to_string())
            .collect();
        assert!(gaps.iter().any(|g| g.starts_with("2.8.f")));
        assert!(gaps.iter().any(|g| g.starts_with("3.5.c(1)")));
        assert!(!gaps.iter().any(|g| g.starts_with("3.5.b")));
        let md = markdown(&idx);
        assert!(md.contains("| 3.5.b |"));
    }

    #[test]
    fn sarif_light_check() {
        let v = json!({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "clippy"}}, "results": [{}, {}]}]});
        assert_eq!(sarif_summary(&v), Some((vec!["clippy".to_string()], 2)));
        assert_eq!(sarif_summary(&json!({"version": "1"})), None);
    }
}
