# Changelog

## 0.3.0

Breaking: sbom-attest now fails by default when an SBOM does not match the build.

**Why.** A published SBOM is a claim nobody checks. Generators read `cargo metadata`
(feature-unified across the whole workspace and every platform), the source tree, or
the lockfile, and none of them is the build. The result ships as the record of what is
in the product, and CVE and license decisions are made from it. A check that only
reports and exits 0 changes nothing, so the checks now fail unless they are switched
off by name.

- New `sbom-attest audit <sbom>`: verifies a published CycloneDX or SPDX SBOM against
  the build's own evidence: `Cargo.lock` (versions and SHA-256), the crate graph
  `cargo tree` resolves for the target and features (`--target auto` reads the target
  cargo-cyclonedx records), the cargo-auditable list in a released `--binary`,
  `compile_commands.json` / build logs / linker maps for C/C++, the C libraries that
  `-sys`/`-src` crates compile from source (`openssl-src 300.3.1+3.3.1` means OpenSSL
  3.3.1 is in the binary), and vendored C/C++ under `third_party/`, `vendor/`,
  `external/`, `deps/` and git submodules. Ten checks: `omitted`, `omitted-build`,
  `vendored-c`, `version-drift`, `hash-drift`, `phantom`, `unpinned`, `unhashed`,
  `yanked` (crates.io sparse index) and `no-license`.
- Every check fails by default. `--waive <check>` is the only way off; each waiver is
  printed as a warning and written into the report. A check that cannot run (for
  example the yanked check under `--offline`) fails too, because an unverified claim
  is not a passing one. Exit codes: 0 pass, 1 findings, 2 error.
- `diff` now exits 1 when the SBOMs disagree. `--report-only` restores the old exit 0;
  `--fail-on-findings` is accepted and does nothing.
- GitHub Action (`uses: Mattbusel/sbom-attest@v0.3.0`): runs the audit, writes the
  report to the job summary, and fails the job on findings.
- Library: `audit` module (`audit`, `Truth`, `AuditReport`, `Class`, `Finding`,
  `parse_lock`, `cargo_graph`, `scan_vendored`, `vendored_by_crate`, `fetch_index`);
  `read::DocComponent` gains `cpe` (a struct-literal change).

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
