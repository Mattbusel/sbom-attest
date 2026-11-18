# Using sbom-attest as a library

sbom-attest is a CLI and a Rust library. The library is what you embed when SBOM
generation belongs inside an existing build tool, `xtask`, release script or CI
service rather than a separate step.

## Add it

```toml
[dependencies]
# SBOM generation, reading, CISA 2026 check and diff. Deps: anyhow, serde_json, sha2.
sbom-attest = { version = "0.2", default-features = false }

# Add signing (P-256, cosign-compatible detached signatures, DSSE, JSF):
# sbom-attest = { version = "0.2", default-features = false, features = ["sign"] }

# Add reading built artifacts (ELF/PE/Mach-O hashes, cargo-auditable data, DT_NEEDED):
# sbom-attest = { version = "0.2", default-features = false, features = ["binary"] }
```

| feature  | adds | extra dependencies |
|----------|------|--------------------|
| (none)   | `generate`, CycloneDX 1.6 and SPDX 2.3 output, `load_sbom`, CISA 2026 check, `diff_sboms`, in-toto/SLSA statements (unsigned) | `anyhow`, `serde_json`, `sha2` |
| `sign`   | `sbom_attest::sign` | `p256`, `rand_core`, `base64` |
| `binary` | `sbom_attest::binary` and `GenerateOptions::with_binary` | `goblin`, `miniz_oxide` |
| `cli` (default) | the `sbom-attest` binary; turns on `sign` and `binary` | `clap` |

MSRV is Rust 1.85. License MIT OR Apache-2.0.

## Stable API

Everything at the crate root is the supported surface. The modules (`cdx`, `spdx`,
`cc`, `cargo_src`, ...) stay public for advanced use but may change in a minor
release.

| item | what it does |
|------|--------------|
| `generate(&GenerateOptions) -> Result<Inventory>` | build the component inventory from Cargo and/or C/C++ inputs |
| `GenerateOptions::cargo(manifest)` / `::cc(root, compile_commands)` | starting points; chain `with_target`, `with_binary`, `with_build_log`, `with_link_map`, `with_author`, `with_producer`, `with_product`, `with_timestamp` |
| `CargoOptions::new(manifest)` | finer Cargo control: `package`, `features`, `all_features`, `no_default_features`, `offline`, `locked` |
| `to_cyclonedx(&Inventory) -> Value` | CycloneDX 1.6 JSON |
| `to_spdx(&Inventory, namespace_base) -> Value` | SPDX 2.3 JSON |
| `load_sbom(path) -> Result<(Doc, Value)>` | read any CycloneDX or SPDX JSON, from any producer |
| `check_minimum_elements(&Doc, signed) -> Vec<Element>` | CISA 2026 minimum elements; `check::score` gives 0-100 |
| `diff_sboms(&vendor, &independent) -> DiffReport` | undeclared, unverified, version and hash mismatches |
| `write(path, bytes)` / `pretty(&Value)` | write with parent dirs / pretty JSON plus newline |

`GenerateOptions` and `CargoOptions` gain fields in minor releases. Build them with
the constructors, or with a struct literal that ends in `..Default::default()`.

## Recipes

### Rust project

```rust
use sbom_attest::{generate, pretty, to_cyclonedx, write, GenerateOptions};

let opts = GenerateOptions::cargo("Cargo.toml")
    .with_target("thumbv7em-none-eabihf")   // resolve target-conditional deps
    .with_author("Example Corp")
    .with_timestamp(1_700_000_000);         // reproducible output
let inv = generate(&opts)?;
write("target/sbom.cdx.json", &pretty(&to_cyclonedx(&inv)))?;
```

`SOURCE_DATE_EPOCH` is honored when no timestamp is given.

### C/C++ build (CMake, Ninja, Make)

```rust
use sbom_attest::{generate, GenerateOptions};

let opts = GenerateOptions::cc(".", "build/compile_commands.json")
    .with_build_log("build/build.log")       // ninja -v / make VERBOSE=1 output
    .with_link_map("build/firmware.map")     // which archive members were linked
    .with_product("firmware", "1.4.2");
let inv = generate(&opts)?;
```

Mixed builds work too: start from `GenerateOptions::cargo` and set
`compile_commands`, `build_log` or `link_maps` on the same options.

### Gate a release on the CISA 2026 minimum elements

```rust
let (doc, _) = sbom_attest::load_sbom("target/sbom.cdx.json")?;
let score = sbom_attest::check::score(&sbom_attest::check_minimum_elements(&doc, false));
anyhow::ensure!(score >= 90.0, "SBOM scores {score:.0}/100 against CISA 2026");
```

### Check a supplier's SBOM against your own build

```rust
let (vendor, _) = sbom_attest::load_sbom("vendor/sbom.spdx.json")?;
let (ours, _) = sbom_attest::load_sbom("target/sbom.cdx.json")?;
let report = sbom_attest::diff_sboms(&vendor, &ours);
for c in &report.undeclared {
    println!("shipped but not declared: {} {:?}", c.name, c.version);
}
```

### Sign (feature `sign`)

```rust
use sbom_attest::sign;

let sk = sign::load_signing_key("env:SBOM_SIGNING_KEY")?; // PKCS#8 P-256 PEM, or a path
let mut doc = sbom_attest::to_cyclonedx(&inv);
sign::jsf_sign(&sk, &mut doc);                            // JSF inside the document
let bytes = sbom_attest::pretty(&doc);
sbom_attest::write("sbom.cdx.json", &bytes)?;
sbom_attest::write("sbom.cdx.json.sig", sign::sign_blob(&sk, &bytes).as_bytes())?;
```

The `.sig` file verifies with
`cosign verify-blob --key sbom.pub --signature sbom.cdx.json.sig --insecure-ignore-tlog=true sbom.cdx.json`.
`sign::keygen()` creates a key pair; `sign::dsse_sign` wraps an in-toto statement from
`provenance::slsa_statement` or `provenance::sbom_statement`.

## Without Rust code: CI

```yaml
- run: cargo install sbom-attest --locked
- run: sbom-attest generate --cdx sbom.cdx.json --spdx sbom.spdx.json --author "Example Corp"
- run: sbom-attest check sbom.cdx.json --min-score 90
```

## Examples

- [`examples/cargo_sbom.rs`](../examples/cargo_sbom.rs): CycloneDX + SPDX for a Cargo
  project and a CISA 2026 score. `cargo run --example cargo_sbom --no-default-features -- Cargo.toml`
- [`examples/sign_sbom.rs`](../examples/sign_sbom.rs): JSF + detached signature.
  `cargo run --example sign_sbom --no-default-features --features sign -- Cargo.toml`
