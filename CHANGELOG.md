# Changelog

## 0.2.0

Library-friendly release. The CLI is unchanged.

- Cargo features: `cli` (default; the binary, adds clap), `sign` (P-256, DSSE, JSF,
  cosign-compatible signatures) and `binary` (ELF/PE/Mach-O and cargo-auditable
  reading). With `default-features = false` the library depends only on `anyhow`,
  `serde_json` and `sha2` (16 crates in the normal dependency tree instead of 80).
- Stable crate-root API: `GenerateOptions::cargo` / `::cc` with `with_*` builders,
  `CargoOptions::new`, `to_cyclonedx`, `to_spdx`, `load_sbom`,
  `check_minimum_elements`, `diff_sboms`; `write` takes `impl AsRef<Path>`.
- `sign::signing_key_from_pem`, and `sign::SigningKey` / `sign::VerifyingKey`
  re-exported so callers need no direct `p256` dependency.
- `util::canonical` (RFC 8785 JCS) moved out of `sign`; `sign::canonical` still works.
- `docs/library.md`, `examples/cargo_sbom.rs`, `examples/sign_sbom.rs`, library API
  tests, and CI jobs for each feature set, rustdoc and the MSRV (1.85) library build.

## 0.1.0

First release: build-time CycloneDX 1.6 and SPDX 2.3 SBOMs for Rust and C/C++,
CISA 2026 minimum elements check, vendor SBOM diff, signed in-toto/SLSA provenance,
DoWI 8430.01 evidence bundle.
