//! in-toto Statement v1 with a SLSA Provenance v1 predicate, and an SBOM attestation
//! statement (predicate type `https://cyclonedx.org/bom`).

use crate::cdx::{TOOL_NAME, TOOL_REPO, TOOL_VERSION};
use crate::util::{sha256, sha256_file, slash};
use anyhow::Result;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;

pub const STATEMENT_V1: &str = "https://in-toto.io/Statement/v1";
pub const SLSA_V1: &str = "https://slsa.dev/provenance/v1";
pub const CYCLONEDX_PREDICATE: &str = "https://cyclonedx.org/bom";
pub const BUILD_TYPE: &str = "https://github.com/Mattbusel/sbom-attest/buildtypes/local-build/v1";

pub fn subject(path: &Path) -> Result<Value> {
    Ok(json!({
        "name": path.file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_default(),
        "digest": {"sha256": sha256_file(path)?},
    }))
}

fn git(dir: &Path, args: &[&str]) -> Option<String> {
    let o = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .ok()?;
    o.status
        .success()
        .then(|| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Remove credentials from a remote URL.
pub fn scrub_url(u: &str) -> String {
    match (u.find("://"), u.find('@')) {
        (Some(s), Some(a)) if a > s => format!("{}{}", &u[..s + 3], &u[a + 1..]),
        _ => u.to_string(),
    }
}

#[derive(Clone, Debug, Default)]
pub struct ProvenanceInput {
    pub subjects: Vec<PathBuf>,
    pub source_dir: PathBuf,
    pub builder_id: Option<String>,
    /// files the build read that should be pinned by digest (Cargo.lock, compile_commands.json)
    pub inputs: Vec<PathBuf>,
    /// files produced alongside (the SBOMs)
    pub byproducts: Vec<PathBuf>,
    pub build_command: Option<String>,
    pub target: Option<String>,
    pub started: Option<String>,
    pub finished: String,
}

/// The SLSA v1 provenance statement. No user name, host name or absolute path is
/// written (DoWI 8430.01 para 3.5.c(2): minimise personal information in evidence).
pub fn slsa_statement(p: &ProvenanceInput) -> Result<Value> {
    let subjects: Vec<Value> = p
        .subjects
        .iter()
        .map(|s| subject(s))
        .collect::<Result<_>>()?;
    let mut resolved = Vec::new();
    let commit = git(&p.source_dir, &["rev-parse", "HEAD"]);
    let remote =
        git(&p.source_dir, &["config", "--get", "remote.origin.url"]).map(|u| scrub_url(&u));
    let dirty = git(
        &p.source_dir,
        &["status", "--porcelain", "--untracked-files=no"],
    )
    .is_some();
    if let Some(c) = &commit {
        resolved.push(json!({
            "uri": format!("git+{}", remote.clone().unwrap_or_else(|| "local".into())),
            "digest": {"gitCommit": c},
            "annotations": {"dirty": dirty},
        }));
    }
    for f in &p.inputs {
        if let Ok(d) = sha256_file(f) {
            resolved.push(json!({
                "name": f.file_name().map(|x| x.to_string_lossy().to_string()).unwrap_or_default(),
                "digest": {"sha256": d},
            }));
        }
    }
    let byproducts: Vec<Value> = p
        .byproducts
        .iter()
        .filter_map(|f| {
            sha256_file(f).ok().map(|d| {
                json!({
                    "name": f.file_name().map(|x| x.to_string_lossy().to_string()).unwrap_or_default(),
                    "digest": {"sha256": d},
                })
            })
        })
        .collect();
    let mut external = json!({});
    if let Some(r) = &remote {
        external["repository"] = json!(r);
    }
    if let Some(c) = &commit {
        external["ref"] = json!(c);
    }
    if let Some(cmd) = &p.build_command {
        external["buildCommand"] = json!(cmd);
    }
    if let Some(t) = &p.target {
        external["target"] = json!(t);
    }
    let mut meta = json!({ "finishedOn": p.finished });
    if let Some(s) = &p.started {
        meta["startedOn"] = json!(s);
    }
    // invocation id: digest of what identifies this run, so it is stable for a rebuild
    let inv_seed = format!("{:?}{:?}{}", commit, subjects, p.finished);
    meta["invocationId"] = json!(format!("urn:sha256:{}", sha256(inv_seed.as_bytes())));
    Ok(json!({
        "_type": STATEMENT_V1,
        "subject": subjects,
        "predicateType": SLSA_V1,
        "predicate": {
            "buildDefinition": {
                "buildType": BUILD_TYPE,
                "externalParameters": external,
                "internalParameters": {"sbomTool": format!("{TOOL_NAME}@{TOOL_VERSION}")},
                "resolvedDependencies": resolved,
            },
            "runDetails": {
                "builder": {
                    "id": p.builder_id.clone().unwrap_or_else(|| format!("{TOOL_REPO}/local-builder@v{TOOL_VERSION}")),
                },
                "metadata": meta,
                "byproducts": byproducts,
            },
        },
    }))
}

/// An in-toto statement carrying a CycloneDX SBOM as its predicate.
pub fn sbom_statement(subjects: &[PathBuf], cdx: &Value) -> Result<Value> {
    let subjects: Vec<Value> = subjects.iter().map(|s| subject(s)).collect::<Result<_>>()?;
    Ok(json!({
        "_type": STATEMENT_V1,
        "subject": subjects,
        "predicateType": CYCLONEDX_PREDICATE,
        "predicate": cdx,
    }))
}

/// Check that every subject file matches a digest in the statement.
pub fn check_subjects(statement: &Value, files: &[PathBuf]) -> Result<()> {
    let subs = statement["subject"].as_array().cloned().unwrap_or_default();
    for f in files {
        let d = sha256_file(f)?;
        if !subs.iter().any(|s| s["digest"]["sha256"] == d.as_str()) {
            anyhow::bail!(
                "{} (sha256 {d}) is not a subject of the attestation",
                slash(f)
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrubs_credentials() {
        assert_eq!(
            scrub_url("https://user:tok@github.com/a/b"),
            "https://github.com/a/b"
        );
        assert_eq!(scrub_url("git@github.com:a/b"), "git@github.com:a/b");
    }

    #[test]
    fn statement_shape() {
        let dir = std::env::temp_dir().join(format!("sbom-attest-prov-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("fw.bin");
        std::fs::write(&f, b"firmware").unwrap();
        let st = slsa_statement(&ProvenanceInput {
            subjects: vec![f.clone()],
            source_dir: dir.clone(),
            finished: "2026-11-17T00:00:00Z".into(),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(st["_type"], STATEMENT_V1);
        assert_eq!(st["predicateType"], SLSA_V1);
        assert_eq!(st["subject"][0]["digest"]["sha256"], sha256(b"firmware"));
        check_subjects(&st, std::slice::from_ref(&f)).unwrap();
        std::fs::write(&f, b"tampered").unwrap();
        assert!(check_subjects(&st, &[f]).is_err());
        std::fs::remove_dir_all(dir).ok();
    }
}
