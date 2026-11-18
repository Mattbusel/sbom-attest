use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use sbom_attest::{bundle, cargo_src, cdx, check, provenance, read, sign, spdx, util};
use sbom_attest::{generate, pretty, write, GenerateOptions};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "sbom-attest",
    version,
    about = "Build-time SBOMs, SBOM diffs and signed provenance for Rust and C/C++ builds"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args, Clone)]
struct GenArgs {
    /// Cargo.toml to scan (default: ./Cargo.toml when it exists)
    #[arg(long)]
    manifest_path: Option<PathBuf>,
    /// Skip the Rust side even if a Cargo.toml exists
    #[arg(long)]
    no_cargo: bool,
    /// Workspace package that produces the artifact
    #[arg(short, long)]
    package: Option<String>,
    /// Target triple; features and dependencies are resolved for it
    #[arg(long)]
    target: Option<String>,
    /// Cargo features to enable (comma separated)
    #[arg(long, value_delimiter = ',')]
    features: Vec<String>,
    #[arg(long)]
    all_features: bool,
    #[arg(long)]
    no_default_features: bool,
    /// Pass --offline to cargo
    #[arg(long)]
    offline: bool,
    /// Pass --locked to cargo
    #[arg(long)]
    locked: bool,
    /// compile_commands.json of the C/C++ build
    #[arg(long)]
    compile_commands: Option<PathBuf>,
    /// Verbose build log (make VERBOSE=1, ninja -v, cmake --build . -v)
    #[arg(long)]
    build_log: Option<PathBuf>,
    /// Linker map file (GNU ld -Map or lld --Map); repeatable
    #[arg(long = "link-map")]
    link_maps: Vec<PathBuf>,
    /// The built artifact (ELF, PE, Mach-O or .a): hashed, and its embedded
    /// cargo-auditable data and shared-library list are read
    #[arg(long)]
    binary: Option<PathBuf>,
    /// Project root: files under it are first party (default: cargo workspace or cwd)
    #[arg(long)]
    project_root: Option<PathBuf>,
    /// Name of the product (default: package or directory name)
    #[arg(long)]
    name: Option<String>,
    /// Version of the product (default: package version or git describe)
    #[arg(long = "product-version")]
    product_version: Option<String>,
    /// Describe the artifact as firmware
    #[arg(long)]
    firmware: bool,
    /// Producer of the product (CISA 2026 "Component Producer"), e.g. your company
    #[arg(long)]
    producer: Option<String>,
    /// Directory the build log's relative paths start from (default: the build
    /// directory recorded in compile_commands.json)
    #[arg(long)]
    build_dir: Option<PathBuf>,
    /// Do not ask dpkg which package owns system files
    #[arg(long)]
    no_dpkg: bool,
    /// SBOM author: the organization producing the SBOM
    #[arg(long)]
    author: Option<String>,
    /// SBOM timestamp as a Unix time (default: SOURCE_DATE_EPOCH, else now)
    #[arg(long)]
    timestamp: Option<i64>,
    /// Add the memory-safe-language property to every component
    #[arg(long)]
    memsafe: bool,
}

impl GenArgs {
    fn options(&self) -> GenerateOptions {
        let manifest = self.manifest_path.clone().or_else(|| {
            let p = PathBuf::from("Cargo.toml");
            p.is_file().then_some(p)
        });
        let cargo = if self.no_cargo {
            None
        } else {
            manifest.map(|m| cargo_src::CargoOptions {
                manifest_path: m,
                package: self.package.clone(),
                target: self.target.clone(),
                features: self.features.clone(),
                all_features: self.all_features,
                no_default_features: self.no_default_features,
                offline: self.offline,
                locked: self.locked,
            })
        };
        GenerateOptions {
            cargo,
            project_root: self.project_root.clone(),
            name: self.name.clone().or_else(|| self.package.clone()),
            version: self.product_version.clone(),
            firmware: self.firmware,
            compile_commands: self.compile_commands.clone(),
            build_log: self.build_log.clone(),
            link_maps: self.link_maps.clone(),
            binary: self.binary.clone(),
            build_dir: self.build_dir.clone(),
            producer: self.producer.clone(),
            use_dpkg: !self.no_dpkg,
            author: self.author.clone(),
            timestamp: self.timestamp,
            memsafe: self.memsafe,
        }
    }
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate CycloneDX 1.6 and/or SPDX 2.3 SBOMs
    Generate {
        #[command(flatten)]
        gen: GenArgs,
        /// CycloneDX JSON output (default: sbom.cdx.json unless --spdx only)
        #[arg(long)]
        cdx: Option<PathBuf>,
        /// SPDX JSON output
        #[arg(long)]
        spdx: Option<PathBuf>,
        /// Sign with this PKCS#8 P-256 key (path or env:VAR): JSF inside the CycloneDX
        /// document plus a detached <file>.sig next to each output
        #[arg(long)]
        key: Option<String>,
        /// Base URI for the SPDX documentNamespace
        #[arg(long, default_value = "https://spdx.org/spdxdocs")]
        spdx_namespace: String,
    },
    /// Score an SBOM against the CISA 2026 minimum elements
    Check {
        sbom: PathBuf,
        /// Detached signature to verify (counts toward SBOM Author Signature)
        #[arg(long)]
        signature: Option<PathBuf>,
        /// Public key for the signature (and for an embedded JSF signature)
        #[arg(long = "pub")]
        public: Option<PathBuf>,
        /// Fail below this score (0-100)
        #[arg(long)]
        min_score: Option<f64>,
        #[arg(long, default_value = "md")]
        format: String,
    },
    /// Compare a vendor SBOM with an independently generated one
    Diff {
        #[arg(long)]
        vendor: PathBuf,
        #[arg(long)]
        independent: PathBuf,
        #[arg(long, default_value = "md")]
        format: String,
        /// Exit 1 when there are undeclared, unverified or mismatched components
        #[arg(long)]
        fail_on_findings: bool,
    },
    /// Create a P-256 key pair (<prefix>.key, <prefix>.pub)
    Keygen {
        #[arg(long, default_value = "sbom-attest")]
        out: PathBuf,
    },
    /// Detached-sign a file (cosign verify-blob compatible)
    Sign {
        file: PathBuf,
        #[arg(long)]
        key: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Verify a detached signature
    Verify {
        file: PathBuf,
        #[arg(long)]
        signature: PathBuf,
        #[arg(long = "pub")]
        public: PathBuf,
    },
    /// Verify the JSF signature embedded in a CycloneDX document
    VerifySbom {
        sbom: PathBuf,
        #[arg(long = "pub")]
        public: Option<PathBuf>,
    },
    /// Write signed in-toto SLSA v1 provenance (DSSE) for build artifacts
    Attest {
        /// Artifact(s) the provenance is about
        #[arg(long = "subject", required = true)]
        subjects: Vec<PathBuf>,
        #[arg(long)]
        key: String,
        #[arg(long, default_value = "provenance.intoto.json")]
        out: PathBuf,
        /// Also write an SBOM attestation for this CycloneDX file
        #[arg(long)]
        sbom: Option<PathBuf>,
        #[arg(long)]
        builder_id: Option<String>,
        /// Inputs to pin by digest (Cargo.lock, compile_commands.json, ...)
        #[arg(long = "input")]
        inputs: Vec<PathBuf>,
        #[arg(long)]
        build_command: Option<String>,
        #[arg(long, default_value = ".")]
        source_dir: PathBuf,
    },
    /// Verify a DSSE attestation and, optionally, that files are its subjects
    VerifyAttestation {
        envelope: PathBuf,
        #[arg(long = "pub")]
        public: PathBuf,
        #[arg(long = "subject")]
        subjects: Vec<PathBuf>,
    },
    /// Write a release evidence bundle
    Bundle {
        #[command(flatten)]
        gen: GenArgs,
        /// Evidence profile
        #[arg(long, default_value = "dowi-8430")]
        profile: String,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        key: String,
        /// SARIF 2.1.0 results (static analysis, fuzzing); repeatable
        #[arg(long)]
        sarif: Vec<PathBuf>,
        /// The supplier's SBOM to compare against the independent one
        #[arg(long)]
        vendor_sbom: Option<PathBuf>,
        /// Record of AI models/versions/datasets used (DoWI 8430.01 3.6.f)
        #[arg(long)]
        ai_record: Option<PathBuf>,
        /// Handling marking written into the index
        #[arg(long, default_value = "UNCLASSIFIED // no CUI")]
        marking: String,
        #[arg(long)]
        builder_id: Option<String>,
        #[arg(long)]
        build_command: Option<String>,
    },
}

fn sibling_sig(p: &Path) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(".sig");
    PathBuf::from(s)
}

fn write_sboms(
    gen: &GenArgs,
    cdx_out: Option<&Path>,
    spdx_out: Option<&Path>,
    key: Option<&str>,
    ns: &str,
) -> Result<(sbom_attest::model::Inventory, Option<Value>)> {
    let inv = generate(&gen.options())?;
    let sk = key.map(sign::load_signing_key).transpose()?;
    let mut cdx_doc = None;
    if let Some(path) = cdx_out {
        let mut doc = cdx::document(&inv);
        if let Some(sk) = &sk {
            sign::jsf_sign(sk, &mut doc);
        }
        let bytes = pretty(&doc);
        write(path, &bytes)?;
        if let Some(sk) = &sk {
            write(sibling_sig(path), sign::sign_blob(sk, &bytes).as_bytes())?;
        }
        eprintln!(
            "wrote {} ({} components)",
            path.display(),
            inv.components.len()
        );
        cdx_doc = Some(doc);
    }
    if let Some(path) = spdx_out {
        let doc = spdx::document(&inv, ns);
        let bytes = pretty(&doc);
        write(path, &bytes)?;
        if let Some(sk) = &sk {
            write(sibling_sig(path), sign::sign_blob(sk, &bytes).as_bytes())?;
        }
        eprintln!("wrote {}", path.display());
    }
    Ok((inv, cdx_doc))
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(2);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Generate {
            gen,
            cdx,
            spdx,
            key,
            spdx_namespace,
        } => {
            let cdx = match (&cdx, &spdx) {
                (None, None) => Some(PathBuf::from("sbom.cdx.json")),
                _ => cdx,
            };
            write_sboms(
                &gen,
                cdx.as_deref(),
                spdx.as_deref(),
                key.as_deref(),
                &spdx_namespace,
            )?;
        }
        Cmd::Check {
            sbom,
            signature,
            public,
            min_score,
            format,
        } => {
            let (doc, raw) = read::load(&sbom)?;
            let mut detached = false;
            if let (Some(sig), Some(p)) = (&signature, &public) {
                let vk = sign::load_verifying_key(p)?;
                sign::verify_blob(&vk, &std::fs::read(&sbom)?, &std::fs::read_to_string(sig)?)
                    .context("detached signature")?;
                detached = true;
            }
            if doc.signed {
                let vk = public
                    .as_ref()
                    .map(|p| sign::load_verifying_key(p))
                    .transpose()?;
                sign::jsf_verify(&raw, vk.as_ref()).context("embedded signature")?;
            }
            let el = check::minimum_elements(&doc, detached);
            if format == "json" {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&check::elements_json(&el))?
                );
            } else {
                print!("{}", check::elements_markdown(&el));
            }
            if let Some(min) = min_score {
                let s = check::score(&el);
                if s < min {
                    bail!("score {s:.1} is below the minimum {min}");
                }
            }
        }
        Cmd::Diff {
            vendor,
            independent,
            format,
            fail_on_findings,
        } => {
            let (v, _) = read::load(&vendor)?;
            let (i, _) = read::load(&independent)?;
            let r = check::diff(&v, &i);
            if format == "json" {
                println!("{}", serde_json::to_string_pretty(&r.to_json())?);
            } else {
                print!(
                    "{}",
                    r.to_markdown(&util::slash(&vendor), &util::slash(&independent))
                );
            }
            if fail_on_findings && !r.clean() {
                std::process::exit(1);
            }
        }
        Cmd::Keygen { out } => {
            let (private, public) = sign::keygen()?;
            let k = out.with_extension("key");
            let p = out.with_extension("pub");
            if k.exists() {
                bail!("{} exists; not overwriting", k.display());
            }
            write(&k, private.as_bytes())?;
            write(&p, public.as_bytes())?;
            eprintln!("wrote {} and {}", k.display(), p.display());
        }
        Cmd::Sign { file, key, out } => {
            let sk = sign::load_signing_key(&key)?;
            let sig = sign::sign_blob(&sk, &std::fs::read(&file)?);
            let out = out.unwrap_or_else(|| sibling_sig(&file));
            write(&out, sig.as_bytes())?;
            eprintln!("wrote {}", out.display());
        }
        Cmd::Verify {
            file,
            signature,
            public,
        } => {
            let vk = sign::load_verifying_key(&public)?;
            sign::verify_blob(
                &vk,
                &std::fs::read(&file)?,
                &std::fs::read_to_string(&signature)?,
            )?;
            println!("Verified OK");
        }
        Cmd::VerifySbom { sbom, public } => {
            let v: Value = serde_json::from_slice(&std::fs::read(&sbom)?)?;
            let vk = public
                .as_ref()
                .map(|p| sign::load_verifying_key(p))
                .transpose()?;
            let kid = sign::jsf_verify(&v, vk.as_ref())?;
            println!("Verified OK (key {})", &kid[..16]);
        }
        Cmd::Attest {
            subjects,
            key,
            out,
            sbom,
            builder_id,
            inputs,
            build_command,
            source_dir,
        } => {
            let sk = sign::load_signing_key(&key)?;
            let st = provenance::slsa_statement(&provenance::ProvenanceInput {
                subjects: subjects.clone(),
                source_dir,
                builder_id,
                inputs,
                byproducts: sbom.iter().cloned().collect(),
                build_command,
                target: None,
                started: None,
                finished: util::timestamp(None),
            })?;
            let env = sign::dsse_sign(&sk, sign::DSSE_INTOTO, &serde_json::to_vec(&st)?);
            write(&out, &pretty(&env))?;
            eprintln!("wrote {}", out.display());
            if let Some(s) = sbom {
                let doc: Value = serde_json::from_slice(&std::fs::read(&s)?)?;
                let st = provenance::sbom_statement(&subjects, &doc)?;
                let env = sign::dsse_sign(&sk, sign::DSSE_INTOTO, &serde_json::to_vec(&st)?);
                let p = out.with_file_name("sbom.intoto.json");
                write(&p, &pretty(&env))?;
                eprintln!("wrote {}", p.display());
            }
        }
        Cmd::VerifyAttestation {
            envelope,
            public,
            subjects,
        } => {
            let vk = sign::load_verifying_key(&public)?;
            let env: Value = serde_json::from_slice(&std::fs::read(&envelope)?)?;
            let payload = sign::dsse_verify(&vk, &env)?;
            let st: Value = serde_json::from_slice(&payload)?;
            provenance::check_subjects(&st, &subjects)?;
            println!(
                "Verified OK: {} with {} subject(s)",
                st["predicateType"].as_str().unwrap_or("?"),
                st["subject"].as_array().map(|a| a.len()).unwrap_or(0)
            );
        }
        Cmd::Bundle {
            gen,
            profile,
            out,
            key,
            sarif,
            vendor_sbom,
            ai_record,
            marking,
            builder_id,
            build_command,
        } => {
            if profile != "dowi-8430" {
                bail!("unknown profile {profile} (available: dowi-8430)");
            }
            run_bundle(
                &gen,
                &out,
                &key,
                &sarif,
                vendor_sbom.as_deref(),
                ai_record.as_deref(),
                &marking,
                builder_id,
                build_command,
            )?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_bundle(
    gen: &GenArgs,
    out: &Path,
    key: &str,
    sarif: &[PathBuf],
    vendor: Option<&Path>,
    ai_record: Option<&Path>,
    marking: &str,
    builder_id: Option<String>,
    build_command: Option<String>,
) -> Result<()> {
    std::fs::create_dir_all(out)?;
    let sk = sign::load_signing_key(key)?;
    let vk = *sk.verifying_key();
    let mut entries: Vec<bundle::Entry> = Vec::new();
    let mut add = |rel: &str, role: &str, note: String| -> Result<()> {
        entries.push(bundle::Entry {
            path: rel.to_string(),
            sha256: util::sha256_file(&out.join(rel))?,
            role: role.into(),
            note,
        });
        Ok(())
    };

    let cdx_p = out.join("sbom.cdx.json");
    let spdx_p = out.join("sbom.spdx.json");
    let (inv, cdx_doc) = write_sboms(
        gen,
        Some(&cdx_p),
        Some(&spdx_p),
        Some(key),
        "https://spdx.org/spdxdocs",
    )?;
    let cdx_doc = cdx_doc.expect("cdx written");
    add(
        "sbom.cdx.json",
        "sbom-cyclonedx",
        format!(
            "CycloneDX 1.6, {} components, JSF ES256 signed",
            inv.components.len()
        ),
    )?;
    add(
        "sbom.cdx.json.sig",
        "signature",
        "detached ECDSA P-256 signature (cosign verify-blob)".into(),
    )?;
    add("sbom.spdx.json", "sbom-spdx", "SPDX 2.3".into())?;
    add(
        "sbom.spdx.json.sig",
        "signature",
        "detached ECDSA P-256 signature".into(),
    )?;
    write(
        out.join("signing-key.pub"),
        sign::public_pem(&sk)?.as_bytes(),
    )?;
    add(
        "signing-key.pub",
        "public-key",
        format!("key id {}", &sign::key_id(&vk)[..16]),
    )?;

    let doc = read::from_cyclonedx(&cdx_doc);
    let el = check::minimum_elements(&doc, true);
    write(
        out.join("min-elements.json"),
        &pretty(&check::elements_json(&el)),
    )?;
    write(
        out.join("min-elements.md"),
        check::elements_markdown(&el).as_bytes(),
    )?;
    add(
        "min-elements.json",
        "min-elements",
        format!("CISA 2026 minimum elements score {:.1}", check::score(&el)),
    )?;

    let mut details = json!({ "minimumElementsScore": (check::score(&el) * 10.0).round() / 10.0 });
    if let Some(v) = vendor {
        std::fs::copy(v, out.join("vendor-sbom.json"))?;
        add(
            "vendor-sbom.json",
            "vendor-sbom",
            format!(
                "supplied by vendor ({})",
                v.file_name().unwrap_or_default().to_string_lossy()
            ),
        )?;
        let (vd, _) = read::load(v)?;
        let r = check::diff(&vd, &doc);
        write(out.join("sbom-diff.json"), &pretty(&r.to_json()))?;
        write(
            out.join("sbom-diff.md"),
            r.to_markdown("vendor-sbom.json", "sbom.cdx.json")
                .as_bytes(),
        )?;
        add(
            "sbom-diff.json",
            "sbom-diff",
            format!(
                "{} matched, {} undeclared, {} unverified, {} version and {} hash mismatches",
                r.matched,
                r.undeclared.len(),
                r.unverified.len(),
                r.version_mismatch.len(),
                r.hash_mismatch.len()
            ),
        )?;
        details["diff"] = r.to_json();
    }
    if !sarif.is_empty() {
        std::fs::create_dir_all(out.join("sarif"))?;
    }
    for s in sarif {
        let v: Value = serde_json::from_slice(&std::fs::read(s)?)
            .with_context(|| format!("{} is not JSON", s.display()))?;
        let Some((tools, n)) = bundle::sarif_summary(&v) else {
            bail!("{} is not SARIF 2.1.0", s.display());
        };
        let name = format!(
            "sarif/{}",
            s.file_name().unwrap_or_default().to_string_lossy()
        );
        std::fs::copy(s, out.join(&name))?;
        add(
            &name,
            "sarif",
            format!("{} ({n} results)", tools.join(", ")),
        )?;
    }
    if let Some(a) = ai_record {
        let name = format!(
            "ai-record.{}",
            a.extension()
                .map(|e| e.to_string_lossy().to_string())
                .unwrap_or_else(|| "txt".into())
        );
        std::fs::copy(a, out.join(&name))?;
        add(
            &name,
            "ai-record",
            "models, versions and datasets used (supplied)".into(),
        )?;
    }

    // provenance: about the binary when there is one, else about the SBOMs
    let subjects: Vec<PathBuf> = match &gen.binary {
        Some(b) => vec![b.clone()],
        None => vec![cdx_p.clone(), spdx_p.clone()],
    };
    let mut inputs = Vec::new();
    if let Some(cc) = &gen.compile_commands {
        inputs.push(cc.clone());
    }
    if let Some(m) = gen.options().cargo.map(|c| c.manifest_path) {
        let lock = m.parent().map(|p| p.join("Cargo.lock")).unwrap_or_default();
        if lock.is_file() {
            inputs.push(lock);
        }
    }
    let st = provenance::slsa_statement(&provenance::ProvenanceInput {
        subjects: subjects.clone(),
        source_dir: gen
            .project_root
            .clone()
            .unwrap_or_else(|| PathBuf::from(".")),
        builder_id,
        inputs,
        byproducts: vec![cdx_p.clone(), spdx_p.clone()],
        build_command,
        target: inv.target.clone(),
        started: None,
        finished: inv.timestamp.clone(),
    })?;
    write(
        out.join("provenance.intoto.json"),
        &pretty(&sign::dsse_sign(
            &sk,
            sign::DSSE_INTOTO,
            &serde_json::to_vec(&st)?,
        )),
    )?;
    add(
        "provenance.intoto.json",
        "provenance",
        "in-toto Statement v1, SLSA Provenance v1, DSSE signed".into(),
    )?;
    let sst = provenance::sbom_statement(&subjects, &cdx_doc)?;
    write(
        out.join("sbom.intoto.json"),
        &pretty(&sign::dsse_sign(
            &sk,
            sign::DSSE_INTOTO,
            &serde_json::to_vec(&sst)?,
        )),
    )?;
    add(
        "sbom.intoto.json",
        "sbom-attestation",
        "in-toto Statement v1 with the CycloneDX SBOM as predicate, DSSE signed".into(),
    )?;

    let root = json!({
        "name": inv.root.name, "version": inv.root.version, "purl": inv.root.purl,
        "sha256": inv.root.sha256(), "hashSubject": inv.root.hash_subject,
    });
    let idx = bundle::index(&entries, marking, &root, details);
    let idx_bytes = pretty(&idx);
    write(out.join("index.json"), &idx_bytes)?;
    write(
        out.join("index.json.sig"),
        sign::sign_blob(&sk, &idx_bytes).as_bytes(),
    )?;
    write(out.join("INDEX.md"), bundle::markdown(&idx).as_bytes())?;

    // SHA256SUMS over everything in the bundle
    let mut files = Vec::new();
    fn walk(dir: &Path, base: &Path, out: &mut Vec<String>) -> Result<()> {
        for e in std::fs::read_dir(dir)? {
            let p = e?.path();
            if p.is_dir() {
                walk(&p, base, out)?;
            } else if p.file_name().is_some_and(|f| f != "SHA256SUMS") {
                out.push(util::slash(p.strip_prefix(base).unwrap_or(&p)));
            }
        }
        Ok(())
    }
    walk(out, out, &mut files)?;
    files.sort();
    let mut sums = String::new();
    for f in &files {
        sums.push_str(&format!("{}  {}\n", util::sha256_file(&out.join(f))?, f));
    }
    write(out.join("SHA256SUMS"), sums.as_bytes())?;
    let gaps = idx["gaps"].as_array().map(|a| a.len()).unwrap_or(0);
    eprintln!(
        "wrote evidence bundle {} ({} files, {} core gaps)",
        out.display(),
        files.len() + 1,
        gaps
    );
    Ok(())
}
