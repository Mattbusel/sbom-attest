//! Generate a CycloneDX SBOM, embed a JSF signature and write a detached signature
//! that `cosign verify-blob --key sbom.pub --signature sbom.cdx.json.sig` accepts.
//!
//!     cargo run --example sign_sbom --features sign -- path/to/Cargo.toml
//!
//! Uses a throwaway key; in CI load yours with `sign::load_signing_key("env:SBOM_KEY")`.

use sbom_attest::{sign, GenerateOptions};

fn main() -> anyhow::Result<()> {
    let manifest = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "Cargo.toml".into());
    let (private_pem, public_pem) = sign::keygen()?;
    let sk = sign::signing_key_from_pem(&private_pem)?;

    let inv = sbom_attest::generate(&GenerateOptions::cargo(&manifest))?;
    let mut doc = sbom_attest::to_cyclonedx(&inv);
    sign::jsf_sign(&sk, &mut doc);
    let bytes = sbom_attest::pretty(&doc);
    sbom_attest::write("target/sbom/sbom.cdx.json", &bytes)?;
    sbom_attest::write(
        "target/sbom/sbom.cdx.json.sig",
        sign::sign_blob(&sk, &bytes).as_bytes(),
    )?;
    sbom_attest::write("target/sbom/sbom.pub", public_pem.as_bytes())?;

    let key_id = sign::jsf_verify(&doc, None)?;
    println!(
        "signed {} components, key id {}",
        inv.components.len(),
        &key_id[..16.min(key_id.len())]
    );
    Ok(())
}
