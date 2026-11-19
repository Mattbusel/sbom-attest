# sbom-attest: your SBOM probably describes a build you didn't ship

[![crates.io](https://img.shields.io/crates/v/sbom-attest.svg)](https://crates.io/crates/sbom-attest)
[![docs.rs](https://docs.rs/sbom-attest/badge.svg)](https://docs.rs/sbom-attest)
[![CI](https://github.com/Mattbusel/sbom-attest/actions/workflows/ci.yml/badge.svg)](https://github.com/Mattbusel/sbom-attest/actions/workflows/ci.yml)

An SBOM generated from the source tree describes what could have been built, not what was. In one automotive release, the binary was built with extra features and the SBOM without them, so it was missing 44 components, axum, hyper and tungstenite among them ([merged fix](https://github.com/eclipse-kuksa/kuksa-databroker/pull/244)). C and C++ are worse: on an opendroneid-core-c build, syft 1.56.0 finds none of the vendored MAVLink library, the shared libraries or the system packages that went into the binary (checked in CI here). sbom-attest builds the SBOM from the build itself.

Build-time SBOMs for mixed Rust and C/C++ builds, including embedded firmware, from
one static binary:

- **Rust:** `cargo metadata` plus `cargo tree`, so dependencies and features are
  resolved for the real `--target`. Crate hashes come from `Cargo.lock`. The
  dependency list that [cargo-auditable](https://github.com/rust-secure-code/cargo-auditable)
  embeds in a binary is read too.
- **C/C++:** `compile_commands.json`, the headers each compile used (from depfiles,
  or from `.ninja_deps` for Ninja builds), the build log's link and `ar` lines, and
  GNU ld / lld linker maps, which name every archive member the linker actually
  pulled in. That is how statically linked libraries nobody declared show up.
- **Binary:** the artifact is hashed, and its shared libraries (DT_NEEDED), RUNPATH,
  compiler identification and GNU build id are read (ELF, PE, Mach-O, `.a`).
- **Output:** CycloneDX 1.6 JSON and SPDX 2.3 JSON carrying the
  [CISA 2026 SBOM minimum elements](https://www.cisa.gov/resources-tools/resources/2026-minimum-elements-software-bill-materials-sbom),
  signed with ECDSA P-256.
- **Diff:** a vendor SBOM against an independently built one (the SWFT pattern).
- **Attest:** in-toto Statement v1 with SLSA Provenance v1, in a DSSE envelope that
  `cosign verify-blob-attestation` accepts.
- **Evidence bundle:** `--profile dowi-8430` writes a release evidence bundle indexed
  to DoW Instruction 8430.01, *Accelerated Mission Software* (effective September 8, 2026).

```sh
cargo install sbom-attest
```

## Quick start

A Rust crate, for the target you ship:

```sh
sbom-attest generate --target thumbv7em-none-eabihf --author "Example Corp" \
  --cdx sbom.cdx.json --spdx sbom.spdx.json
```

A C/C++ build (CMake + Ninja shown; Make works the same with `make VERBOSE=1`):

```sh
cmake -S . -B build -G Ninja -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  -DCMAKE_C_LINK_EXECUTABLE="<CMAKE_C_COMPILER> <FLAGS> <CMAKE_C_LINK_FLAGS> <LINK_FLAGS> <OBJECTS> -o <TARGET> -Wl,-Map=<TARGET>.map <LINK_LIBRARIES>"
ninja -C build -v > build.log

sbom-attest generate --no-cargo --project-root . \
  --compile-commands build/compile_commands.json --build-log build.log \
  --binary build/firmware.elf --firmware --producer "Example Corp" --author "Example Corp" \
  --cdx sbom.cdx.json --spdx sbom.spdx.json
```

With `--binary`, only what that artifact's link step pulled in is reported: the
objects it linked, the archives and shared libraries this build produced for it, and
their own inputs. Other executables in the same `compile_commands.json` (test
binaries, tools) are left out, and the SBOM says how many compile units were kept.

Sign, check, diff, attest:

```sh
sbom-attest keygen --out release                     # release.key, release.pub
sbom-attest generate ... --key release.key           # JSF signature inside, plus .sig files
sbom-attest check sbom.cdx.json --pub release.pub --signature sbom.cdx.json.sig --min-score 90
sbom-attest diff --vendor supplier.cdx.json --independent sbom.cdx.json --fail-on-findings
sbom-attest attest --subject build/firmware.elf --key release.key --sbom sbom.cdx.json
```

Verify with standard tools:

```sh
cosign verify-blob --key release.pub --signature sbom.cdx.json.sig --insecure-ignore-tlog=true sbom.cdx.json
cosign verify-blob-attestation --key release.pub --signature provenance.intoto.json \
  --type slsaprovenance1 --insecure-ignore-tlog=true build/firmware.elf
```

## Use it as a library

Generate SBOMs from your own build tool, xtask or release script:

```toml
[dependencies]
sbom-attest = { version = "0.2", default-features = false }  # anyhow, serde_json, sha2 only
```

```rust
let inv = sbom_attest::generate(&sbom_attest::GenerateOptions::cargo("Cargo.toml"))?;
sbom_attest::write("target/sbom.cdx.json", &sbom_attest::pretty(&sbom_attest::to_cyclonedx(&inv)))?;
sbom_attest::write("target/sbom.spdx.json", &sbom_attest::pretty(&sbom_attest::to_spdx(&inv, "https://spdx.org/spdxdocs")))?;
```

Features: `sign` (P-256, DSSE, JSF, cosign-compatible signatures), `binary` (read
ELF/PE/Mach-O, cargo-auditable data) and `cli` (the binary; default). See
[docs/library.md](docs/library.md) for the full API, C/C++ inputs, signing and CI
recipes, and [examples/](examples/).

## CISA 2026 minimum elements

| Element | CycloneDX 1.6 | SPDX 2.3 |
|---|---|---|
| SBOM Author | `metadata.authors` (`--author`) | `creationInfo.creators` Organization |
| SBOM Author Signature | JSF ES256 `signature` + detached `.sig` | detached `.sig` |
| SBOM Data Format Name / Version | `bomFormat`, `specVersion` | `spdxVersion` |
| SBOM Generation Context | `metadata.lifecycles`: pre-build, build, post-build, from the inputs used | `creationInfo.comment` |
| SBOM Timestamp | `metadata.timestamp` (`SOURCE_DATE_EPOCH` honoured) | `creationInfo.created` |
| SBOM Tool Name / Version | `metadata.tools.components` | `Tool: sbom-attest-<version>` |
| SBOM Version | `serialNumber` (derived from content) + `version` | `documentNamespace` |
| Component Name / Version | `name`, `version` | `name`, `versionInfo` |
| Component Producer | `authors`, `supplier` | `supplier` |
| Component Identifiers | `purl` (cargo, deb, or generic with checksum / VCS) | `externalRefs` purl |
| Component Hash Value / Algorithm | `hashes` (SHA-256, SHA-512 for the artifact) | `checksums` |
| Component License | `licenses` (declared) | `licenseDeclared` |
| Component Dependency Relationship | `dependencies` | `DEPENDS_ON`, `BUILD_DEPENDENCY_OF` |

What each hash covers is recorded in the `sbom-attest:hash-subject` property:
`crate-archive` (the `.crate` digest from `Cargo.lock`), `binary`, `archive`,
`shared-object`, or `source-files` (a digest over the sorted file paths and their
SHA-256, so it does not depend on where the tree is checked out). When no hash is
possible the component says `sbom-attest:hash=unknown`, as the CISA document asks.

## Target-conditional features

`cargo metadata` unifies features across every platform, even with
`--filter-platform` ([rust-lang/cargo#9863](https://github.com/rust-lang/cargo/issues/9863)).
A crate that enables `dep/a` on musl and `dep/b` elsewhere gets both in an SBOM built
from it. sbom-attest takes the graph from `cargo tree --target`, which runs cargo's
feature resolver. `tests/fixtures/target-cfg-features` is that case; CI checks it
against `cargo-cyclonedx` 0.5.10, which lists the extra crate.

## The DoWI 8430.01 evidence bundle

```sh
sbom-attest bundle --profile dowi-8430 --out evidence/ --key release.key \
  --binary build/firmware.elf --compile-commands build/compile_commands.json --build-log build.log \
  --sarif clippy.sarif --sarif fuzz.sarif --vendor-sbom supplier.cdx.json --author "Example Corp"
```

writes the SBOMs (signed), the CISA minimum-elements report, the vendor diff, SLSA
provenance and an SBOM attestation (DSSE), the SARIF files, `SHA256SUMS`, and an
index (`index.json`, signed, and `INDEX.md`) that maps each file to the paragraph it
is evidence for:

| Paragraph | Asks for | Bundle files |
|---|---|---|
| 2.8.f | static and dynamic analysis, fuzz testing | `sarif/*` |
| 2.8.k | SBOMs for custom software, captured SBOMs for COTS, provenance and pedigree | SBOMs, vendor SBOM and diff, provenance |
| 3.5.a(1) | machine-readable evidence of composition, build integrity, application security | SBOM, provenance, SARIF |
| 3.5.b | an accurate SBOM for vulnerability and license management | SBOMs, minimum-elements report, diff |
| 3.5.c(1) | machine-readable provenance and attestations that provide pedigree | provenance, SBOM attestation, signatures |
| 3.5.c(2) | marking, and minimal personal information | marking in the index; no user or host names, paths relative or `~` |
| 3.5.i(4) | third-party and transitive dependencies in the SBOM | SBOM, diff |
| 3.6.f | record of AI models and datasets used | `--ai-record` |

The index is a map of evidence to paragraphs, not a compliance determination. The
DoW CIO defines the evidence formats (para 3.5.a(2)) and the authorizing official
decides. Missing evidence for the core paragraphs is listed under `gaps`.

## Conformance tests

`ci/conformance.sh` runs on every push (Ubuntu 24.04):

- every CycloneDX output validates against the official CycloneDX 1.6 JSON schema
  (with format checking) and with `cyclonedx validate` (cyclonedx-cli 0.33.1); every
  SPDX output passes `pyspdxtools` (spdx-tools 0.8.3);
- `sbomqs` 2.1.3 CISA 2026 ("ntia") profile score of at least 9.0/10 for each SBOM
  with dependencies;
- Rust: same component set and crate hashes as `cargo-cyclonedx` 0.5.10 on
  remoteid, misb, uas-cot, mavlink-tlog and sbom-attest itself (66 crates), and the
  one expected difference on the target-conditional fixture;
- C: an opendroneid-core-c build (pinned commit) is described from its own build:
  the vendored `mavlink_c_library_v2` submodule, the shared libraries the test binary
  loads, and the Debian packages whose headers, CRT objects and libraries went in.
  `syft` 1.56.0 finds none of these from the source tree or the binary;
- two clean builds of opendroneid-core-c give identical component hashes;
- `cosign verify-blob` accepts the detached signatures, `cosign
  verify-blob-attestation` accepts the provenance and SBOM attestations for the
  binary and rejects them for a different file.

## Limits

- Linker maps: GNU ld and lld formats. MSVC, IAR and Keil maps are not parsed yet.
- Package ownership: `dpkg` only (no rpm or apk yet). Licenses of Debian packages
  are read only from machine-readable copyright files.
- Licenses are the ones the producer declared; nothing is concluded. LICENSE file
  detection is a text match for common licenses.
- Keys are unencrypted PKCS#8 P-256 PEM (file or `env:VAR`). No keyless signing or
  transparency log.
- The provenance describes a local build. It is SLSA Provenance v1 format; the build
  platform decides which SLSA build level it meets.
- `--memsafe` marks Rust components `true` (`rust-ffi` for `-sys` crates and crates
  with a `links` key) and C, C++ and assembly `false`. It is a language property, not
  an analysis.

## MSRV and license

Minimum supported Rust version: 1.85 (checked in CI). Raising it is a minor-version
change.

MIT OR Apache-2.0. Maintained by Matt Busel ([Tensorust](https://tensorust.com));
issues and PRs welcome.
