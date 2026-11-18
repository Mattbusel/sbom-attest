# Changelog

## 0.2.1

- Fix: a binary's DT_NEEDED libraries are only resolved to library files built for
  the same ELF machine. Before, an ARM binary cross-compiled on an x86_64 host had
  `libc.so.6`, `libm.so.6` and the rest resolved to the host's x86_64 files, and the
  SBOM carried those paths and hashes. Now those stay soname-only when no matching
  library is on the search path. `cc::elf_machine` is new and `cc::resolve_needed`
  takes the expected machine.
- Fix: when `--binary` is combined with a cargo scan, the binary's cargo-auditable
  list is now a cross-check instead of a second source of components. cargo-auditable
  records the `cargo metadata` graph, which unifies features across the workspace and
  can name crates that are never compiled in (on linkerd2-proxy: ring, proptest,
  quickcheck, tokio-test and 17 more, none of them present in the binary's symbols).
  Components found by both get the `cargo-auditable` evidence; crates only
  cargo-auditable lists go into the `sbom-attest:auditable-only` document property.
  Git dependencies now match their cargo-scan component instead of appearing twice.

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
