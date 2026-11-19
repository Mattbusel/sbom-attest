# sbom-attest: your SBOM is a lie until the build proves it

[![crates.io](https://img.shields.io/crates/v/sbom-attest.svg)](https://crates.io/crates/sbom-attest)
[![docs.rs](https://docs.rs/sbom-attest/badge.svg)](https://docs.rs/sbom-attest)
[![CI](https://github.com/Mattbusel/sbom-attest/actions/workflows/ci.yml/badge.svg)](https://github.com/Mattbusel/sbom-attest/actions/workflows/ci.yml)

Nobody checks a published SBOM against the build it claims to describe. On November 19
2026 we took the SBOM that 32 Rust projects attach to their latest GitHub release
(made by cargo-cyclonedx, syft, cargo-sbom, cdxgen and others) and checked each one
against the `Cargo.lock` and crate graph of its own release tag. **All 32 fail.**

- **23 of 32** build or link a C library into the release that the SBOM never names.
  The SBOM lists the Rust wrapper (`openssl-src`, `curl-sys`, `zstd-sys`,
  `aws-lc-sys`, `libsqlite3-sys`), so an OpenSSL, curl or SQLite advisory never
  matches the product. One `x86_64-unknown-linux-gnu` SBOM alone omits OpenSSL 3.6.3,
  curl 8.21.0, librdkafka 2.12.1, lz4 1.10.0, zstd 1.5.7, AWS-LC and zlib.
- **19 of 32** ship a crate version that crates.io has yanked (async-executor 1.14.0,
  spin 0.9.8, chacha20 0.10.1, crypto-bigint 0.7.6 ...), and no SBOM says so.
- **29 of 32** declare crates the release cannot contain: outside the crate graph even
  with `--all-features --target all`. cargo-cyclonedx reads `cargo metadata`, which
  unifies features across the workspace, so one 282-component SBOM lists 62 crates
  (termwiz, pest, palette ...) that cargo never compiles into that binary.
- **2** list no dependencies at all for binaries whose `Cargo.lock` holds 819 and
  1,296 third-party crates.

Per-project data, with `Cargo.lock` line links and the SBOM asset URLs:
[`reports/release-sboms-2026-11.json`](reports/release-sboms-2026-11.json). This is
not about the maintainers: they ran the standard tools, and the standard tools do not
look at the build.

`sbom-attest audit` is the check, and it fails by default:

```sh
cargo install sbom-attest
sbom-attest audit dist/app.cdx.json            # in the workspace the release was built from
```

| Check | Fails when |
|---|---|
| `omitted` | a crate the build links is not in the SBOM |
| `omitted-build` | a proc macro or build-script dependency (code that runs during your build) is not in the SBOM |
| `vendored-c` | a `-sys`/`-src` crate builds a C library in (`openssl-src 300.6.1+3.6.3` is OpenSSL 3.6.3), or `third_party/`, `vendor/`, `external/` or a submodule holds C/C++, and no SBOM component names that library |
| `version-drift` | the SBOM's version is not the one `Cargo.lock` or the C build uses |
| `hash-drift` | the SBOM's SHA-256 is not the one `Cargo.lock` or crates.io pins |
| `phantom` | the SBOM declares a crate the build does not compile (not in `Cargo.lock`, or outside the graph for the target and features) |
| `unpinned` | a component has no exact version |
| `unhashed` | a component has no hash although `Cargo.lock` pins one |
| `yanked` | the build uses a crate version yanked from crates.io |
| `no-license` | a component has no license |

What the build contains comes from the build's own evidence: `Cargo.lock`, the graph
`cargo tree` resolves for the target and features (`--target auto` reads the target
cargo-cyclonedx records in the SBOM), the cargo-auditable list in a released
`--binary`, `--compile-commands` / `--build-log` / `--link-map` for C and C++, and the
source tree. A check that cannot run fails too: `--offline` skips crates.io, so
`yanked` fails as not run. An unverified claim is not a pass.

The opt-out is loud on purpose. `--waive <check>` is the only way to turn a check off;
each waiver is printed as a warning and written into the report, so whoever reads it
knows exactly what was not verified. Exit codes: 0 pass, 1 findings, 2 error.

```sh
sbom-attest audit sbom.cdx.json --package my-app --target x86_64-unknown-linux-gnu \
  --features tls,metrics --json audit.json --summary audit.md
sbom-attest audit sbom.cdx.json --binary target/release/my-app   # cargo-auditable data, no Cargo.toml needed
sbom-attest audit sbom.cdx.json --waive no-license                # warns: this run accepts components without a license
```

### GitHub Action

```yaml
- run: cargo cyclonedx --format json      # or syft, cargo-sbom: anything that writes CycloneDX/SPDX JSON
- uses: Mattbusel/sbom-attest@v0.3.0
  with:
    sbom: my-app.cdx.json
    package: my-app            # optional: the workspace package the SBOM describes
    features: tls,metrics      # optional: the features the release is built with
    # waive: no-license        # optional; written into the job summary when used
```

The report goes to the job summary and the job fails on any finding. This repository
runs the Action on its own SBOM in CI, and it passes.

## Build an SBOM from the build

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
sbom-attest = { version = "0.3", default-features = false }  # anyhow, serde_json, sha2 only
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

- `audit` knows which `-sys`/`-src` crates carry C source from the `+<upstream
  version>` convention, a list of common crates and their bundling features; a crate
  that vendors C without any of these is not caught. Vendored C/C++ in the source tree
  is matched to SBOM components by directory name.
- `audit` matches crates by name and version (purl when present). Graph checks need
  `cargo tree` to resolve the workspace, so registry access or a vendored registry.

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
