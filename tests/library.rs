//! The crate-root library API, with no optional features required.

use sbom_attest::{CargoOptions, GenerateOptions};
use std::path::{Path, PathBuf};

fn fixture(p: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(p)
}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("sbom-attest-lib-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn options() -> GenerateOptions {
    let mut o = GenerateOptions::cargo(fixture("target-cfg-features/app/Cargo.toml"))
        .with_target("x86_64-unknown-linux-gnu")
        .with_author("Example Corp")
        .with_timestamp(1_763_337_600);
    o.cargo.as_mut().unwrap().offline = true;
    o
}

#[test]
fn generate_write_load_check_and_diff() {
    let inv = sbom_attest::generate(&options()).unwrap();
    assert!(inv.components.values().any(|c| c.name == "y"));
    assert!(!inv.components.values().any(|c| c.name == "x"));

    let out = tmp("api");
    let cdx = out.join("nested/sbom.cdx.json");
    let spdx = out.join("sbom.spdx.json");
    sbom_attest::write(&cdx, &sbom_attest::pretty(&sbom_attest::to_cyclonedx(&inv))).unwrap();
    sbom_attest::write(
        &spdx,
        &sbom_attest::pretty(&sbom_attest::to_spdx(&inv, "https://example.com/spdxdocs")),
    )
    .unwrap();

    let (cdx_doc, raw) = sbom_attest::load_sbom(&cdx).unwrap();
    assert_eq!(raw["specVersion"], "1.6");
    assert_eq!(cdx_doc.author.as_deref(), Some("Example Corp"));
    let (spdx_doc, raw) = sbom_attest::load_sbom(&spdx).unwrap();
    assert_eq!(raw["spdxVersion"], "SPDX-2.3");

    let score = sbom_attest::check::score(&sbom_attest::check_minimum_elements(&cdx_doc, false));
    assert!(score > 50.0, "score {score}");

    // the same build in two formats: nothing undeclared, nothing unverified
    let report = sbom_attest::diff_sboms(&spdx_doc, &cdx_doc);
    assert!(report.undeclared.is_empty(), "{:?}", report.undeclared);
    assert!(report.unverified.is_empty(), "{:?}", report.unverified);
    assert!(report.matched > 0);
}

#[test]
fn library_output_is_reproducible() {
    let a = sbom_attest::to_cyclonedx(&sbom_attest::generate(&options()).unwrap());
    let b = sbom_attest::to_cyclonedx(&sbom_attest::generate(&options()).unwrap());
    assert_eq!(a, b);
    assert_eq!(a["metadata"]["timestamp"], "2025-11-17T00:00:00Z");
}

#[test]
fn struct_literal_with_default_still_works() {
    let o = GenerateOptions {
        cargo: Some(CargoOptions {
            offline: true,
            ..CargoOptions::new(fixture("target-cfg-features/app/Cargo.toml"))
        }),
        timestamp: Some(0),
        ..Default::default()
    };
    assert!(sbom_attest::generate(&o).is_ok());
}

#[cfg(not(feature = "binary"))]
#[test]
fn binary_input_without_the_feature_is_a_clear_error() {
    let err = sbom_attest::generate(&options().with_binary("firmware.elf")).unwrap_err();
    assert!(err.to_string().contains("`binary` feature"), "{err}");
}
