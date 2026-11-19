#![cfg(feature = "cli")]
//! End-to-end tests that run the sbom-attest binary.

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sbom-attest"))
}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("sbom-attest-it-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn fixture(p: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(p)
}

fn run_ok(cmd: &mut Command) -> String {
    let o = cmd.output().unwrap();
    assert!(
        o.status.success(),
        "{cmd:?} failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8_lossy(&o.stdout).to_string()
}

fn names(doc: &Value) -> Vec<String> {
    let mut v: Vec<String> = doc["components"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap().to_string())
        .collect();
    v.sort();
    v
}

/// cargo metadata --filter-platform unifies features across platforms
/// (rust-lang/cargo#9863). The SBOM must follow the features the target really gets.
#[test]
fn target_conditional_features_follow_the_target() {
    let out = tmp("cfg");
    let manifest = fixture("target-cfg-features/app/Cargo.toml");
    for (target, want, not) in [
        ("x86_64-unknown-linux-musl", "x", "y"),
        ("x86_64-unknown-linux-gnu", "y", "x"),
    ] {
        let path = out.join(format!("{target}.cdx.json"));
        run_ok(
            bin()
                .arg("generate")
                .arg("--manifest-path")
                .arg(&manifest)
                .args(["--offline", "--target", target, "--timestamp", "0", "--cdx"])
                .arg(&path),
        );
        let doc: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let n = names(&doc);
        assert!(n.contains(&want.to_string()), "{target}: {n:?}");
        assert!(!n.contains(&not.to_string()), "{target}: {n:?}");
        let props = doc["metadata"]["properties"].to_string();
        assert!(props.contains(target));
    }
}

#[test]
fn output_is_reproducible() {
    let out = tmp("repro");
    let manifest = fixture("target-cfg-features/app/Cargo.toml");
    let mut docs = Vec::new();
    for i in 0..2 {
        let cdx = out.join(format!("{i}.cdx.json"));
        let spdx = out.join(format!("{i}.spdx.json"));
        run_ok(
            bin()
                .arg("generate")
                .arg("--manifest-path")
                .arg(&manifest)
                .args(["--offline", "--target", "x86_64-unknown-linux-gnu", "--cdx"])
                .arg(&cdx)
                .arg("--spdx")
                .arg(&spdx)
                .env("SOURCE_DATE_EPOCH", "1763337600"),
        );
        docs.push((std::fs::read(&cdx).unwrap(), std::fs::read(&spdx).unwrap()));
    }
    assert_eq!(
        docs[0].0, docs[1].0,
        "CycloneDX output differs between runs"
    );
    assert_eq!(docs[0].1, docs[1].1, "SPDX output differs between runs");
    let doc: Value = serde_json::from_slice(&docs[0].0).unwrap();
    assert_eq!(doc["metadata"]["timestamp"], "2025-11-17T00:00:00Z");
}

#[test]
fn sign_check_and_verify_roundtrip() {
    let out = tmp("sign");
    let key = out.join("k");
    run_ok(bin().arg("keygen").arg("--out").arg(&key));
    let cdx = out.join("s.cdx.json");
    run_ok(
        bin()
            .arg("generate")
            .arg("--manifest-path")
            .arg(fixture("target-cfg-features/app/Cargo.toml"))
            .args(["--offline", "--author", "Example Org", "--cdx"])
            .arg(&cdx)
            .arg("--key")
            .arg(key.with_extension("key")),
    );
    let pubkey = key.with_extension("pub");
    run_ok(bin().arg("verify-sbom").arg(&cdx).arg("--pub").arg(&pubkey));
    let sig = PathBuf::from(format!("{}.sig", cdx.display()));
    run_ok(
        bin()
            .arg("verify")
            .arg(&cdx)
            .arg("--signature")
            .arg(&sig)
            .arg("--pub")
            .arg(&pubkey),
    );
    let report = run_ok(
        bin()
            .arg("check")
            .arg(&cdx)
            .arg("--signature")
            .arg(&sig)
            .arg("--pub")
            .arg(&pubkey)
            .args(["--format", "json"]),
    );
    let r: Value = serde_json::from_str(&report).unwrap();
    let el = |name: &str| {
        r["elements"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["element"] == name)
            .unwrap()["coverage"]
            .as_f64()
            .unwrap()
    };
    for e in [
        "SBOM Author",
        "SBOM Author Signature",
        "SBOM Tool Name",
        "SBOM Tool Version",
        "SBOM Generation Context",
        "SBOM Timestamp",
        "Component Identifiers",
    ] {
        assert_eq!(el(e), 1.0, "{e}");
    }
    // tamper: the embedded and detached signatures must both fail
    let mut doc: Value = serde_json::from_slice(&std::fs::read(&cdx).unwrap()).unwrap();
    doc["components"][0]["version"] = Value::String("9.9.9".into());
    std::fs::write(&cdx, serde_json::to_vec_pretty(&doc).unwrap()).unwrap();
    assert!(!bin()
        .arg("verify-sbom")
        .arg(&cdx)
        .output()
        .unwrap()
        .status
        .success());
    assert!(!bin()
        .arg("verify")
        .arg(&cdx)
        .arg("--signature")
        .arg(&sig)
        .arg("--pub")
        .arg(&pubkey)
        .output()
        .unwrap()
        .status
        .success());
}

#[test]
fn attest_and_verify_subjects() {
    let out = tmp("attest");
    let key = out.join("k");
    run_ok(bin().arg("keygen").arg("--out").arg(&key));
    let art = out.join("firmware.bin");
    std::fs::write(&art, b"\x7fELF not really").unwrap();
    let env = out.join("prov.intoto.json");
    run_ok(
        bin()
            .arg("attest")
            .arg("--subject")
            .arg(&art)
            .arg("--key")
            .arg(key.with_extension("key"))
            .arg("--out")
            .arg(&env),
    );
    let ok = run_ok(
        bin()
            .arg("verify-attestation")
            .arg(&env)
            .arg("--pub")
            .arg(key.with_extension("pub"))
            .arg("--subject")
            .arg(&art),
    );
    assert!(ok.contains("https://slsa.dev/provenance/v1"));
    std::fs::write(&art, b"changed").unwrap();
    assert!(!bin()
        .arg("verify-attestation")
        .arg(&env)
        .arg("--pub")
        .arg(key.with_extension("pub"))
        .arg("--subject")
        .arg(&art)
        .output()
        .unwrap()
        .status
        .success());
}

#[test]
fn diff_flags_an_undeclared_component() {
    let out = tmp("diff");
    let manifest = fixture("target-cfg-features/app/Cargo.toml");
    let ours = out.join("ours.cdx.json");
    run_ok(
        bin()
            .arg("generate")
            .arg("--manifest-path")
            .arg(&manifest)
            .args(["--offline", "--target", "x86_64-unknown-linux-gnu", "--cdx"])
            .arg(&ours),
    );
    // the "vendor" SBOM leaves out one component and declares one that is not there
    let mut vendor: Value = serde_json::from_slice(&std::fs::read(&ours).unwrap()).unwrap();
    let comps = vendor["components"].as_array_mut().unwrap();
    comps.retain(|c| c["name"] != "y");
    comps.push(serde_json::json!({"type": "library", "name": "ghost", "version": "1.0.0", "purl": "pkg:cargo/ghost@1.0.0"}));
    let vpath = out.join("vendor.cdx.json");
    std::fs::write(&vpath, serde_json::to_vec(&vendor).unwrap()).unwrap();
    let o = bin()
        .arg("diff")
        .arg("--vendor")
        .arg(&vpath)
        .arg("--independent")
        .arg(&ours)
        .args(["--format", "json", "--fail-on-findings"])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1));
    let r: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(r["undeclared"][0]["name"], "y");
    assert_eq!(r["unverified"][0]["name"], "ghost");
    // failing is the default now; --report-only is the explicit opt-out
    let o = bin()
        .arg("diff")
        .arg("--vendor")
        .arg(&vpath)
        .arg("--independent")
        .arg(&ours)
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1));
    let o = bin()
        .arg("diff")
        .arg("--vendor")
        .arg(&vpath)
        .arg("--independent")
        .arg(&ours)
        .arg("--report-only")
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&o.stderr).contains("--report-only"));
}

const AUDIT_LOCK: &str = r#"version = 4

[[package]]
name = "app"
version = "0.1.0"
dependencies = ["serde", "zstd-sys"]

[[package]]
name = "serde"
version = "1.0.210"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaa"

[[package]]
name = "zstd-sys"
version = "2.0.13+zstd.1.5.6"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "bbbb"
"#;

fn audit_sbom(dir: &Path, components: Value) -> PathBuf {
    let doc = serde_json::json!({
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"component": {"type": "application", "name": "app", "version": "0.1.0",
                                   "licenses": [{"expression": "MIT"}]}},
        "components": components,
    });
    let p = dir.join("published.cdx.json");
    std::fs::write(&p, serde_json::to_vec(&doc).unwrap()).unwrap();
    p
}

/// A published SBOM that leaves out a crate and the C library a -sys crate compiles
/// in fails by default; every waiver is announced.
#[test]
fn audit_fails_a_lying_sbom_by_default() {
    let out = tmp("audit");
    let lock = out.join("Cargo.lock");
    std::fs::write(&lock, AUDIT_LOCK).unwrap();
    let sbom = audit_sbom(
        &out,
        serde_json::json!([
            {"type": "library", "name": "serde", "version": "1.0.210",
             "purl": "pkg:cargo/serde@1.0.210", "licenses": [{"expression": "MIT OR Apache-2.0"}],
             "hashes": [{"alg": "SHA-256", "content": "aaaa"}]}
        ]),
    );
    let base = |c: &mut Command| {
        c.arg("audit")
            .arg(&sbom)
            .arg("--lockfile")
            .arg(&lock)
            .arg("--source-dir")
            .arg(&out)
            .arg("--offline");
    };
    let mut c = bin();
    base(&mut c);
    let o = c.args(["--format", "json"]).output().unwrap();
    assert_eq!(
        o.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    let r: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(r["result"], "fail");
    let found: Vec<(String, String)> = r["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["check"].as_str().unwrap().into(),
                f["name"].as_str().unwrap().into(),
            )
        })
        .collect();
    assert!(
        found.contains(&("omitted".into(), "zstd-sys".into())),
        "{found:?}"
    );
    assert!(
        found.contains(&("vendored-c".into(), "zstd".into())),
        "{found:?}"
    );
    assert_eq!(r["notRun"][0]["check"], "yanked");

    // waiving is explicit, loud and recorded in the report
    let mut c = bin();
    base(&mut c);
    let o = c
        .args(["--waive", "omitted,vendored-c", "--waive", "yanked"])
        .output()
        .unwrap();
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&o.stdout)
    );
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(err.contains("WARNING: --waive omitted"), "{err}");
    let md = String::from_utf8_lossy(&o.stdout);
    assert!(md.starts_with("# sbom-attest audit: PASS"), "{md}");
    assert!(md.contains("This SBOM was not verified for"));

    // an unknown check name is an error, not a silent pass
    let mut c = bin();
    base(&mut c);
    let o = c.args(["--waive", "everything"]).output().unwrap();
    assert_eq!(o.status.code(), Some(2));
}

/// The SBOM sbom-attest generates for a workspace passes its own audit against the
/// resolved crate graph.
#[test]
fn audit_passes_its_own_sbom() {
    let out = tmp("audit-self");
    let manifest = fixture("target-cfg-features/app/Cargo.toml");
    let ours = out.join("ours.cdx.json");
    run_ok(
        bin()
            .arg("generate")
            .arg("--manifest-path")
            .arg(&manifest)
            .args(["--offline", "--target", "x86_64-unknown-linux-gnu", "--cdx"])
            .arg(&ours),
    );
    let md = run_ok(
        bin()
            .arg("audit")
            .arg(&ours)
            .arg("--manifest-path")
            .arg(&manifest)
            .args([
                "--offline",
                "--target",
                "x86_64-unknown-linux-gnu",
                "--waive",
                "yanked,no-license",
            ]),
    );
    assert!(md.starts_with("# sbom-attest audit: PASS"), "{md}");
    assert!(md.contains("cargo tree -e normal,build --workspace --target x86_64-unknown-linux-gnu"));
}

#[test]
fn dowi_bundle_indexes_evidence() {
    let out = tmp("bundle");
    let key = out.join("k");
    run_ok(bin().arg("keygen").arg("--out").arg(&key));
    let sarif = out.join("fuzz.sarif");
    std::fs::write(
        &sarif,
        r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"cargo-fuzz"}},"results":[]}]}"#,
    )
    .unwrap();
    let dir = out.join("evidence");
    run_ok(
        bin()
            .arg("bundle")
            .arg("--manifest-path")
            .arg(fixture("target-cfg-features/app/Cargo.toml"))
            .args(["--offline", "--author", "Example Org", "--out"])
            .arg(&dir)
            .arg("--key")
            .arg(key.with_extension("key"))
            .arg("--sarif")
            .arg(&sarif),
    );
    let idx: Value =
        serde_json::from_slice(&std::fs::read(dir.join("index.json")).unwrap()).unwrap();
    assert_eq!(idx["profile"], "dowi-8430");
    assert_eq!(idx["gaps"].as_array().unwrap().len(), 0, "{}", idx["gaps"]);
    let para = |id: &str| {
        idx["paragraphs"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["paragraph"] == id)
            .unwrap()
            .clone()
    };
    assert_eq!(para("2.8.f")["status"], "evidence present");
    assert_eq!(para("3.5.c(1)")["status"], "evidence present");
    assert_eq!(para("3.6.f")["status"], "no evidence supplied");
    for f in [
        "sbom.cdx.json",
        "sbom.spdx.json",
        "provenance.intoto.json",
        "sbom.intoto.json",
        "INDEX.md",
        "SHA256SUMS",
        "index.json.sig",
    ] {
        assert!(dir.join(f).is_file(), "{f}");
    }
    // every SHA256SUMS line matches
    let sums = std::fs::read_to_string(dir.join("SHA256SUMS")).unwrap();
    for line in sums.lines() {
        let (h, f) = line.split_once("  ").unwrap();
        assert_eq!(
            sbom_attest::util::sha256_file(&dir.join(f)).unwrap(),
            h,
            "{f}"
        );
    }
    run_ok(
        bin()
            .arg("verify-attestation")
            .arg(dir.join("provenance.intoto.json"))
            .arg("--pub")
            .arg(dir.join("signing-key.pub"))
            .arg("--subject")
            .arg(dir.join("sbom.cdx.json")),
    );
}

/// A real C build: vendored code under its own LICENSE, a static library, depfiles,
/// a verbose build log and a GNU ld map.
#[cfg(target_os = "linux")]
#[test]
fn c_build_from_compile_commands_log_and_map() {
    if Command::new("cc").arg("--version").output().is_err() {
        eprintln!("no C compiler, skipping");
        return;
    }
    let d = tmp("cbuild");
    std::fs::create_dir_all(d.join("src")).unwrap();
    std::fs::create_dir_all(d.join("third_party/crc/include")).unwrap();
    std::fs::create_dir_all(d.join("build")).unwrap();
    std::fs::write(
        d.join("third_party/crc/LICENSE"),
        "Permission is hereby granted, free of charge, to any person",
    )
    .unwrap();
    std::fs::write(
        d.join("third_party/crc/include/crc.h"),
        "unsigned crc8(const unsigned char*, unsigned);\n",
    )
    .unwrap();
    std::fs::write(
        d.join("third_party/crc/crc.c"),
        "#include \"crc.h\"\nunsigned crc8(const unsigned char*p, unsigned n){unsigned c=0;while(n--)c^=*p++;return c&255;}\n",
    )
    .unwrap();
    std::fs::write(
        d.join("src/main.c"),
        "#include <stdio.h>\n#include \"crc.h\"\nint main(void){printf(\"%u\\n\", crc8((const unsigned char*)\"ab\",2));return 0;}\n",
    )
    .unwrap();
    let b = d.join("build");
    let inc = d.join("third_party/crc/include");
    let mut log = String::new();
    let mut cc_json = Vec::new();
    for (src, obj) in [("third_party/crc/crc.c", "crc.o"), ("src/main.c", "main.o")] {
        let args = vec![
            "cc".to_string(),
            "-O2".into(),
            "-ffile-prefix-map=".to_string() + &d.display().to_string() + "=.",
            format!("-I{}", inc.display()),
            "-MD".into(),
            "-MF".into(),
            format!("{obj}.d"),
            "-c".into(),
            d.join(src).display().to_string(),
            "-o".into(),
            obj.into(),
        ];
        run_ok(Command::new(&args[0]).args(&args[1..]).current_dir(&b));
        log.push_str(&format!("{}\n", args.join(" ")));
        cc_json.push(serde_json::json!({"directory": b, "file": d.join(src), "arguments": args, "output": obj}));
    }
    run_ok(
        Command::new("ar")
            .args(["qcD", "libcrc.a", "crc.o"])
            .current_dir(&b),
    );
    log.push_str("ar qcD libcrc.a crc.o\n");
    let link = [
        "cc",
        "main.o",
        "-o",
        "app",
        "libcrc.a",
        "-Wl,-Map=app.map",
        "-lm",
    ];
    run_ok(Command::new(link[0]).args(&link[1..]).current_dir(&b));
    log.push_str(&format!("{}\n", link.join(" ")));
    std::fs::write(b.join("build.log"), log).unwrap();
    std::fs::write(
        b.join("compile_commands.json"),
        serde_json::to_vec(&cc_json).unwrap(),
    )
    .unwrap();

    let out = b.join("app.cdx.json");
    run_ok(
        bin()
            .arg("generate")
            .arg("--project-root")
            .arg(&d)
            .arg("--compile-commands")
            .arg(b.join("compile_commands.json"))
            .arg("--build-log")
            .arg(b.join("build.log"))
            .arg("--binary")
            .arg(b.join("app"))
            .args([
                "--name",
                "app",
                "--product-version",
                "1.0.0",
                "--memsafe",
                "--cdx",
            ])
            .arg(&out)
            .current_dir(&b),
    );
    let doc: Value = serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
    let comps = doc["components"].as_array().unwrap();
    let find = |n: &str| comps.iter().find(|c| c["name"] == n).cloned();
    let crc = find("crc").expect("vendored crc component");
    assert!(crc["licenses"].to_string().contains("MIT"));
    assert!(
        crc["properties"].to_string().contains("include/crc.h"),
        "depfile header missing"
    );
    let lib = find("libcrc.a").expect("static archive from the build log / map");
    assert!(lib["properties"].to_string().contains("crc.o"));
    assert!(lib["hashes"].is_array());
    let root = &doc["metadata"]["component"];
    assert_eq!(root["name"], "app");
    assert!(root["hashes"].to_string().contains("SHA-512"));
    let phases = doc["metadata"]["lifecycles"].to_string();
    assert!(phases.contains("\"build\"") && phases.contains("post-build"));
    assert!(
        root["properties"].to_string().contains("\"false\""),
        "C root is not memory safe"
    );
}
