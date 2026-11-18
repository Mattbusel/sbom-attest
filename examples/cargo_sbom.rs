//! Generate a CycloneDX 1.6 and an SPDX 2.3 SBOM for a Cargo project, then score the
//! result against the CISA 2026 minimum elements.
//!
//!     cargo run --example cargo_sbom -- path/to/Cargo.toml
//!
//! Works with `default-features = false` (no clap, no crypto, no object parser).

use sbom_attest::{check, GenerateOptions};

fn main() -> anyhow::Result<()> {
    let manifest = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "Cargo.toml".into());

    let inv =
        sbom_attest::generate(&GenerateOptions::cargo(&manifest).with_author("Example Corp"))?;
    sbom_attest::write(
        "target/sbom/sbom.cdx.json",
        &sbom_attest::pretty(&sbom_attest::to_cyclonedx(&inv)),
    )?;
    sbom_attest::write(
        "target/sbom/sbom.spdx.json",
        &sbom_attest::pretty(&sbom_attest::to_spdx(&inv, "https://spdx.org/spdxdocs")),
    )?;

    let (doc, _raw) = sbom_attest::load_sbom("target/sbom/sbom.cdx.json")?;
    let elements = sbom_attest::check_minimum_elements(&doc, false);
    println!(
        "{} components, CISA 2026 minimum elements score {:.0}/100 (unsigned)",
        inv.components.len(),
        check::score(&elements)
    );
    Ok(())
}
