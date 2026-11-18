//! C/C++ components from the build itself: `compile_commands.json` (plus the depfiles
//! the compiler wrote), the build log's link and archive lines, and linker map files.
//!
//! Files are grouped into components by where they live:
//! - under the project root, below no other license or `.git` marker: first party;
//! - under a directory with its own LICENSE/COPYING or `.git` (vendored code,
//!   submodules): one component per such directory;
//! - outside the project and owned by a Debian package (when `dpkg` is present): that
//!   package, with its version, maintainer and a `pkg:deb` purl;
//! - anything else: one component per library file, or per system include directory.

use crate::model::{Component, Inventory, Kind, Lang, Phase, Scope};
use crate::util::{display_path, normalize, purl_escape, sha256_file, slash, tree_digest};
use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    Source,
    Header,
    StaticLib,
    SharedLib,
}

/// One file the build used, and how we know.
#[derive(Clone, Debug)]
pub struct FileFact {
    pub path: PathBuf,
    pub role: Role,
    pub evidence: String,
    /// archive members actually pulled in by the linker
    pub members: BTreeSet<String>,
    pub lang: Lang,
    /// the object file this source or header was compiled into
    pub object: Option<PathBuf>,
}

/// Split a shell command line (handles single/double quotes and backslash escapes).
pub fn shell_split(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut has = false;
    let mut chars = s.chars().peekable();
    let mut quote: Option<char> = None;
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some('"'), '\\') => {
                if let Some(&n) = chars.peek() {
                    if n == '"' || n == '\\' || n == '$' || n == '`' {
                        cur.push(n);
                        chars.next();
                        continue;
                    }
                }
                cur.push('\\');
            }
            (Some(_), c) => cur.push(c),
            (None, '\'' | '"') => {
                quote = Some(c);
                has = true;
            }
            (None, '\\') => {
                if let Some(n) = chars.next() {
                    cur.push(n);
                    has = true;
                }
            }
            (None, c) if c.is_whitespace() => {
                if has || !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                    has = false;
                }
            }
            (None, c) => cur.push(c),
        }
    }
    if has || !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn lang_of(path: &Path) -> Lang {
    match path.extension().and_then(|e| e.to_str()).unwrap_or("") {
        "c" => Lang::C,
        "cc" | "cpp" | "cxx" | "c++" | "C" | "hpp" | "hh" | "hxx" => Lang::Cpp,
        "s" | "S" | "asm" => Lang::Asm,
        _ => Lang::Unknown,
    }
}

/// Parse a Make-style depfile into the prerequisite paths.
pub fn parse_depfile(text: &str) -> Vec<String> {
    let joined = text.replace("\\\r\n", " ").replace("\\\n", " ");
    let mut out = Vec::new();
    for line in joined.lines() {
        // the target is everything before the first ": " (Windows drive letters have no space)
        let Some(idx) = line
            .find(": ")
            .or_else(|| line.strip_suffix(':').map(|l| l.len()))
        else {
            continue;
        };
        let deps = &line[(idx + 1).min(line.len())..];
        let mut cur = String::new();
        let mut it = deps.chars().peekable();
        while let Some(c) = it.next() {
            if c == '\\' && it.peek() == Some(&' ') {
                cur.push(' ');
                it.next();
            } else if c.is_whitespace() {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            } else {
                cur.push(c);
            }
        }
        if !cur.is_empty() {
            out.push(cur);
        }
    }
    out
}

fn abs(dir: &Path, p: &str) -> PathBuf {
    let p = Path::new(p);
    normalize(&if p.is_absolute() {
        p.to_path_buf()
    } else {
        dir.join(p)
    })
}

/// Parse `ninja -t deps` output: object path -> dependency paths.
pub fn parse_ninja_deps(text: &str, dir: &Path) -> HashMap<PathBuf, Vec<PathBuf>> {
    let mut out: HashMap<PathBuf, Vec<PathBuf>> = HashMap::new();
    let mut cur: Option<PathBuf> = None;
    for line in text.lines() {
        if line.trim().is_empty() {
            cur = None;
            continue;
        }
        if !line.starts_with(' ') && !line.starts_with('\t') {
            if let Some(i) = line.find(": #deps") {
                let obj = abs(dir, &line[..i]);
                out.entry(obj.clone()).or_default();
                cur = Some(obj);
            }
            continue;
        }
        if let Some(obj) = &cur {
            out.get_mut(obj).unwrap().push(abs(dir, line.trim()));
        }
    }
    out
}

/// Ninja deletes depfiles once it has read them into `.ninja_deps`; ask it for them.
fn ninja_deps(dir: &Path) -> HashMap<PathBuf, Vec<PathBuf>> {
    if !dir.join(".ninja_deps").is_file() {
        return HashMap::new();
    }
    match Command::new("ninja")
        .arg("-C")
        .arg(dir)
        .args(["-t", "deps"])
        .output()
    {
        Ok(o) if o.status.success() => parse_ninja_deps(&String::from_utf8_lossy(&o.stdout), dir),
        _ => HashMap::new(),
    }
}

/// What `compile_commands.json` says about the build.
#[derive(Clone, Debug, Default)]
pub struct CompileDb {
    pub facts: Vec<FileFact>,
    pub compilers: BTreeSet<String>,
    /// the build directories compiles ran in
    pub dirs: BTreeSet<PathBuf>,
}

/// Read `compile_commands.json`: every source file, plus every header listed in the
/// depfile each compile wrote (or in `.ninja_deps` for Ninja builds).
pub fn read_compile_commands(path: &Path) -> Result<CompileDb> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let entries: Vec<Value> =
        serde_json::from_str(&text).context("parsing compile_commands.json")?;
    let mut db = CompileDb::default();
    let mut ninja: HashMap<PathBuf, HashMap<PathBuf, Vec<PathBuf>>> = HashMap::new();
    for e in entries {
        let dir = normalize(Path::new(e["directory"].as_str().unwrap_or(".")));
        db.dirs.insert(dir.clone());
        let args: Vec<String> = match e["arguments"].as_array() {
            Some(a) => a
                .iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect(),
            None => shell_split(e["command"].as_str().unwrap_or("")),
        };
        if let Some(cc) = args.first() {
            db.compilers.insert(
                Path::new(cc)
                    .file_name()
                    .map(|f| f.to_string_lossy().to_string())
                    .unwrap_or_default(),
            );
        }
        let Some(file) = e["file"].as_str() else {
            continue;
        };
        let src = abs(&dir, file);
        let lang = lang_of(&src);
        // depfile: -MF <file>, or -MD/-MMD next to -o <obj>
        let mut depfile = None;
        let mut output = e["output"].as_str().map(String::from);
        let mut md = false;
        let mut i = 0;
        while i < args.len() {
            let a = &args[i];
            if a == "-MF" {
                depfile = args.get(i + 1).cloned();
                i += 1;
            } else if let Some(f) = a.strip_prefix("-MF") {
                depfile = Some(f.to_string());
            } else if a == "-o" {
                output = args.get(i + 1).cloned();
                i += 1;
            } else if let Some(o) = a.strip_prefix("/Fo") {
                output = Some(o.to_string());
            } else if a == "-MD" || a == "-MMD" {
                md = true;
            }
            i += 1;
        }
        let object = output.as_ref().map(|o| abs(&dir, o));
        db.facts.push(FileFact {
            path: src.clone(),
            role: Role::Source,
            evidence: "compile_commands".into(),
            members: BTreeSet::new(),
            lang,
            object: object.clone(),
        });
        if depfile.is_none() && md {
            depfile = output
                .as_ref()
                .map(|o| slash(&Path::new(o).with_extension("d")));
        }
        let mut deps: Vec<(PathBuf, &str)> = Vec::new();
        if let Some(d) = depfile {
            if let Ok(t) = std::fs::read_to_string(abs(&dir, &d)) {
                deps.extend(parse_depfile(&t).iter().map(|x| (abs(&dir, x), "depfile")));
            }
        }
        if deps.is_empty() {
            if let Some(obj) = &object {
                let table = ninja.entry(dir.clone()).or_insert_with(|| ninja_deps(&dir));
                if let Some(list) = table.get(obj) {
                    deps.extend(list.iter().map(|x| (x.clone(), "ninja-deps")));
                }
            }
        }
        for (p, ev) in deps {
            if p == src {
                continue;
            }
            db.facts.push(FileFact {
                path: p,
                role: Role::Header,
                evidence: ev.into(),
                members: BTreeSet::new(),
                lang,
                object: object.clone(),
            });
        }
    }
    Ok(db)
}

fn is_tool(argv0: &str, names: &[&str]) -> bool {
    let base = Path::new(argv0)
        .file_name()
        .map(|f| f.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let base = base.trim_end_matches(".exe");
    names.iter().any(|n| {
        base == *n
            || base.ends_with(&format!("-{n}"))
            || (base.starts_with(n)
                && base[n.len()..].starts_with('-')
                && base[n.len() + 1..]
                    .chars()
                    .all(|c| c.is_ascii_digit() || c == '.'))
    })
}

const COMPILERS: &[&str] = &[
    "gcc", "g++", "cc", "c++", "clang", "clang++", "ld", "ld.lld", "ld.gold", "ld.bfd", "lld",
    "lld-link", "link", "tcc", "icx", "icpx",
];
const ARCHIVERS: &[&str] = &["ar", "llvm-ar", "gcc-ar", "lib"];

/// What the build log says was linked and archived.
#[derive(Clone, Debug, Default)]
pub struct LinkFacts {
    pub files: Vec<FileFact>,
    /// archive path -> object files put into it
    pub archives: BTreeMap<PathBuf, BTreeSet<String>>,
    /// archive path -> object files put into it (absolute paths)
    pub archive_objects: BTreeMap<PathBuf, BTreeSet<PathBuf>>,
    /// every link step, in log order
    pub links: Vec<LinkStep>,
    /// (map file, directory the linker ran in: paths in the map are relative to it)
    pub map_files: Vec<(PathBuf, PathBuf)>,
    /// -l names that did not resolve to a file
    pub unresolved: BTreeSet<String>,
}

/// One linker invocation from the build log.
#[derive(Clone, Debug, Default)]
pub struct LinkStep {
    pub output: Option<PathBuf>,
    pub objects: Vec<PathBuf>,
    pub libs: Vec<FileFact>,
    pub maps: Vec<(PathBuf, PathBuf)>,
}

impl LinkFacts {
    /// Restrict to what went into `artifact`: its link step, the archives and shared
    /// libraries it linked that this build produced, and their link steps in turn.
    /// Returns the object files reached, or None when no link step produced it.
    pub fn scope_to(&mut self, artifact: &Path) -> Option<BTreeSet<PathBuf>> {
        let name = artifact.file_name()?;
        let start = self.links.iter().position(|l| {
            l.output
                .as_ref()
                .is_some_and(|o| o == artifact || o.file_name() == Some(name))
        })?;
        let mut objects = BTreeSet::new();
        let mut files = Vec::new();
        let mut maps = Vec::new();
        let mut seen_steps = BTreeSet::new();
        let mut queue = vec![start];
        while let Some(i) = queue.pop() {
            if !seen_steps.insert(i) {
                continue;
            }
            let step = self.links[i].clone();
            objects.extend(step.objects.iter().cloned());
            maps.extend(step.maps.iter().cloned());
            for lib in &step.libs {
                files.push(lib.clone());
                if let Some(objs) = self.archive_objects.get(&lib.path) {
                    objects.extend(objs.iter().cloned());
                }
                // a shared library this build linked: follow its own link step
                if let Some(j) = self
                    .links
                    .iter()
                    .position(|l| l.output.as_ref() == Some(&lib.path))
                {
                    queue.push(j);
                }
            }
        }
        self.files = files;
        self.map_files = maps;
        Some(objects)
    }
}

/// The `e_machine` field of an ELF file, or `None` if `path` is not ELF.
pub fn elf_machine(path: &Path) -> Option<u16> {
    use std::io::Read;
    let mut h = [0u8; 20];
    std::fs::File::open(path).ok()?.read_exact(&mut h).ok()?;
    if h[..4] != *b"ELF" {
        return None;
    }
    let m = [h[18], h[19]];
    Some(if h[5] == 2 {
        u16::from_be_bytes(m)
    } else {
        u16::from_le_bytes(m)
    })
}

fn default_lib_dirs() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = vec!["/usr/local/lib".into()];
    for multi in [
        "x86_64-linux-gnu",
        "aarch64-linux-gnu",
        "arm-linux-gnueabihf",
        "i386-linux-gnu",
    ] {
        v.push(format!("/usr/lib/{multi}").into());
        v.push(format!("/lib/{multi}").into());
    }
    v.push("/usr/lib".into());
    v.push("/lib".into());
    v
}

fn find_lib(name: &str, dirs: &[PathBuf], prefer_static: bool) -> Option<PathBuf> {
    let candidates: Vec<String> = if let Some(exact) = name.strip_prefix(':') {
        vec![exact.to_string()]
    } else if prefer_static {
        vec![format!("lib{name}.a"), format!("lib{name}.so")]
    } else {
        vec![format!("lib{name}.so"), format!("lib{name}.a")]
    };
    for d in dirs {
        for c in &candidates {
            let p = d.join(c);
            if p.is_file() {
                return Some(normalize(&p));
            }
        }
    }
    None
}

/// Parse a build log (`make VERBOSE=1`, `ninja -v`, `cmake --build . -v`).
pub fn read_build_log(text: &str, start_dir: &Path) -> LinkFacts {
    let mut facts = LinkFacts::default();
    let mut cwd = start_dir.to_path_buf();
    for raw in text.lines() {
        let mut line = raw.trim();
        // ninja: "[3/7] cmd"
        if line.starts_with('[') {
            if let Some(i) = line.find("] ") {
                line = &line[i + 2..];
            }
        }
        // make: "make[2]: Entering directory '/x'"
        if let Some(i) = line.find("Entering directory") {
            let d = line[i + 18..]
                .trim()
                .trim_matches(|c| c == '\'' || c == '`' || c == '"');
            cwd = PathBuf::from(d);
            continue;
        }
        let mut seg_dir = cwd.clone();
        for seg in line.split("&&") {
            let toks = shell_split(seg.trim());
            if toks.is_empty() {
                continue;
            }
            if toks[0] == "cd" {
                if let Some(d) = toks.get(1) {
                    seg_dir = abs(&seg_dir, d);
                }
                continue;
            }
            let argv0 = toks[0].as_str();
            if is_tool(argv0, ARCHIVERS) {
                // ar <ops> archive members...
                let mut it = toks.iter().skip(1).filter(|t| !t.starts_with('-'));
                let _ops = it.next();
                if let Some(archive) = it.next() {
                    let a = abs(&seg_dir, archive);
                    let members: Vec<&String> = it.collect();
                    let abs_entry = facts.archive_objects.entry(a.clone()).or_default();
                    for m in &members {
                        abs_entry.insert(abs(&seg_dir, m));
                    }
                    let entry = facts.archives.entry(a).or_default();
                    for m in members {
                        entry.insert(
                            Path::new(m)
                                .file_name()
                                .map(|f| f.to_string_lossy().to_string())
                                .unwrap_or_default(),
                        );
                    }
                }
                continue;
            }
            if !is_tool(argv0, COMPILERS) {
                continue;
            }
            if toks.iter().any(|t| t == "-c" || t == "-S" || t == "-E") {
                continue; // a compile, already covered by compile_commands
            }
            // a link
            let prefer_static = toks
                .iter()
                .any(|t| t == "-static" || t == "-Bstatic" || t == "-Wl,-Bstatic");
            let mut lib_dirs = Vec::new();
            let mut libs = Vec::new();
            let mut step = LinkStep::default();
            let mut i = 1;
            while i < toks.len() {
                let t = &toks[i];
                if t == "-o" {
                    step.output = toks.get(i + 1).map(|o| abs(&seg_dir, o));
                    i += 2;
                    continue;
                }
                if t == "-T" || t == "-MF" {
                    i += 2;
                    continue;
                }
                if t == "-L" {
                    if let Some(d) = toks.get(i + 1) {
                        lib_dirs.push(abs(&seg_dir, d));
                    }
                    i += 2;
                    continue;
                }
                if let Some(d) = t.strip_prefix("-L") {
                    lib_dirs.push(abs(&seg_dir, d));
                } else if t == "-l" {
                    if let Some(n) = toks.get(i + 1) {
                        libs.push(n.clone());
                    }
                    i += 1;
                } else if let Some(n) = t.strip_prefix("-l") {
                    libs.push(n.to_string());
                } else if let Some(w) = t.strip_prefix("-Wl,") {
                    let parts: Vec<&str> = w.split(',').collect();
                    for (k, p) in parts.iter().enumerate() {
                        if let Some(m) =
                            p.strip_prefix("-Map=").or_else(|| p.strip_prefix("--Map="))
                        {
                            step.maps.push((abs(&seg_dir, m), seg_dir.clone()));
                        } else if (*p == "-Map" || *p == "--Map") && k + 1 < parts.len() {
                            step.maps
                                .push((abs(&seg_dir, parts[k + 1]), seg_dir.clone()));
                        }
                    }
                } else if !t.starts_with('-') {
                    let lower = t.to_lowercase();
                    let role = if lower.ends_with(".a") || lower.ends_with(".lib") {
                        Some(Role::StaticLib)
                    } else if lower.ends_with(".so")
                        || lower.contains(".so.")
                        || lower.ends_with(".dylib")
                    {
                        Some(Role::SharedLib)
                    } else {
                        None
                    };
                    if lower.ends_with(".o") || lower.ends_with(".obj") {
                        step.objects.push(abs(&seg_dir, t));
                    }
                    if let Some(role) = role {
                        step.libs.push(FileFact {
                            path: abs(&seg_dir, t),
                            role,
                            evidence: "build-log".into(),
                            members: BTreeSet::new(),
                            lang: Lang::Unknown,
                            object: None,
                        });
                    }
                }
                i += 1;
            }
            let mut dirs = lib_dirs.clone();
            dirs.extend(default_lib_dirs());
            for l in libs {
                match find_lib(&l, &dirs, prefer_static) {
                    Some(p) => {
                        let role = if p.extension().is_some_and(|e| e == "a") {
                            Role::StaticLib
                        } else {
                            Role::SharedLib
                        };
                        step.libs.push(FileFact {
                            path: p,
                            role,
                            evidence: "build-log".into(),
                            members: BTreeSet::new(),
                            lang: Lang::Unknown,
                            object: None,
                        });
                    }
                    None => {
                        facts.unresolved.insert(l);
                    }
                }
            }
            facts.files.extend(step.libs.iter().cloned());
            facts.map_files.extend(step.maps.iter().cloned());
            facts.links.push(step);
        }
    }
    facts
}

/// Parse a GNU ld or lld linker map: every archive member the linker actually pulled
/// in, and every file it loaded.
pub fn read_link_map(text: &str, dir: &Path) -> Vec<FileFact> {
    let mut by_archive: BTreeMap<PathBuf, BTreeSet<String>> = BTreeMap::new();
    let mut loaded: BTreeSet<PathBuf> = BTreeSet::new();
    for line in text.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("LOAD ") {
            let p = rest.trim();
            if p.ends_with(".a") || p.ends_with(".so") || p.contains(".so.") {
                loaded.insert(abs(dir, p));
            }
            continue;
        }
        // "path/libx.a(member.o)" anywhere on the line (GNU ld and lld forms)
        for tok in t.split_whitespace() {
            let tok = tok.trim_end_matches([':', ',']);
            let tok = tok.split(":(").next().unwrap_or(tok);
            if let Some(open) = tok.find(".a(") {
                if tok.ends_with(')') {
                    let archive = &tok[..open + 2];
                    let member = &tok[open + 3..tok.len() - 1];
                    by_archive
                        .entry(abs(dir, archive))
                        .or_default()
                        .insert(member.to_string());
                }
            }
        }
    }
    let mut out = Vec::new();
    for (a, members) in by_archive {
        loaded.remove(&a);
        out.push(FileFact {
            path: a,
            role: Role::StaticLib,
            evidence: "linker-map".into(),
            members,
            lang: Lang::Unknown,
            object: None,
        });
    }
    for p in loaded {
        let role = if p.extension().is_some_and(|e| e == "a") {
            Role::StaticLib
        } else {
            Role::SharedLib
        };
        out.push(FileFact {
            path: p,
            role,
            evidence: "linker-map".into(),
            members: BTreeSet::new(),
            lang: Lang::Unknown,
            object: None,
        });
    }
    out
}

/// Debian package owning a file.
#[derive(Clone, Debug)]
pub struct DebPkg {
    pub name: String,
    pub version: String,
    pub arch: String,
    pub maintainer: Option<String>,
    pub homepage: Option<String>,
    pub license: Option<String>,
}

fn dpkg_available() -> bool {
    Command::new("dpkg-query")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn os_release() -> (String, String) {
    let text = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    let get = |k: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(&format!("{k}=")))
            .map(|v| v.trim_matches('"').to_string())
            .unwrap_or_default()
    };
    (get("ID"), get("VERSION_ID"))
}

fn debian_license(pkg: &str) -> Option<String> {
    let base = pkg.split(':').next().unwrap_or(pkg);
    let text = std::fs::read_to_string(format!("/usr/share/doc/{base}/copyright")).ok()?;
    if !text.starts_with("Format:") {
        return None;
    }
    // first "License:" after "Files: *"
    let start = text.find("Files: *")?;
    let lic = text[start..]
        .lines()
        .find_map(|l| l.strip_prefix("License:"))?
        .trim();
    let mapped = match lic {
        "GPL-2+" => "GPL-2.0-or-later",
        "GPL-2" => "GPL-2.0-only",
        "GPL-3+" => "GPL-3.0-or-later",
        "GPL-3" => "GPL-3.0-only",
        "LGPL-2.1+" => "LGPL-2.1-or-later",
        "LGPL-2.1" => "LGPL-2.1-only",
        "LGPL-3+" => "LGPL-3.0-or-later",
        "BSD-3-clause" => "BSD-3-Clause",
        "BSD-2-clause" => "BSD-2-Clause",
        "Expat" => "MIT",
        "BSD-C3" | "BSD-3" => "BSD-3-Clause",
        "Zlib" => "Zlib",
        "Apache-2.0" => "Apache-2.0",
        "ISC" => "ISC",
        other => other,
    };
    Some(mapped.to_string())
}

/// Look up which Debian package owns each path (one `dpkg -S` call).
pub fn dpkg_owners(paths: &[PathBuf]) -> HashMap<PathBuf, DebPkg> {
    let mut out = HashMap::new();
    if paths.is_empty() || !dpkg_available() {
        return out;
    }
    // dpkg records paths as packaged; with merged /usr the file may be listed under /lib
    let mut queries: Vec<(String, PathBuf)> = Vec::new();
    for p in paths {
        let s = slash(p);
        queries.push((s.clone(), p.clone()));
        if let Some(rest) = s.strip_prefix("/usr/lib/") {
            queries.push((format!("/lib/{rest}"), p.clone()));
        } else if let Some(rest) = s.strip_prefix("/lib/") {
            queries.push((format!("/usr/lib/{rest}"), p.clone()));
        }
        if let Ok(c) = std::fs::canonicalize(p) {
            let cs = slash(&c);
            if cs != s {
                queries.push((cs, p.clone()));
            }
        }
    }
    let mut owner_of: HashMap<PathBuf, String> = HashMap::new();
    for chunk in queries.chunks(400) {
        let Ok(o) = Command::new("dpkg")
            .arg("-S")
            .args(chunk.iter().map(|(q, _)| q))
            .output()
        else {
            return out;
        };
        let text = String::from_utf8_lossy(&o.stdout);
        for line in text.lines() {
            if line.starts_with("diversion ") {
                continue;
            }
            let Some((pkgs, file)) = line.split_once(": ") else {
                continue;
            };
            let pkg = pkgs.split(", ").next().unwrap_or(pkgs).to_string();
            for (q, orig) in chunk {
                if q == file.trim() {
                    owner_of.entry(orig.clone()).or_insert_with(|| pkg.clone());
                }
            }
        }
    }
    let names: BTreeSet<String> = owner_of.values().cloned().collect();
    if names.is_empty() {
        return out;
    }
    let Ok(o) = Command::new("dpkg-query")
        .arg("-W")
        .arg("-f=${binary:Package}\t${Package}\t${Version}\t${Architecture}\t${Maintainer}\t${Homepage}\n")
        .args(&names)
        .output()
    else {
        return out;
    };
    let mut info: HashMap<String, DebPkg> = HashMap::new();
    for line in String::from_utf8_lossy(&o.stdout).lines() {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() < 6 {
            continue;
        }
        let d = DebPkg {
            name: f[1].to_string(),
            version: f[2].to_string(),
            arch: f[3].to_string(),
            maintainer: Some(f[4].split('<').next().unwrap_or("").trim().to_string())
                .filter(|s| !s.is_empty()),
            homepage: Some(f[5].to_string()).filter(|s| !s.is_empty()),
            license: debian_license(f[1]),
        };
        info.insert(f[0].to_string(), d.clone());
        info.insert(f[1].to_string(), d);
    }
    for (p, pkg) in owner_of {
        if let Some(d) = info.get(&pkg) {
            out.insert(p, d.clone());
        }
    }
    out
}

/// Recognise the common license texts in a LICENSE/COPYING file.
pub fn detect_license(text: &str) -> Option<&'static str> {
    let t = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let has = |s: &str| t.contains(s);
    if has("Apache License") && has("Version 2.0") {
        Some("Apache-2.0")
    } else if has("GNU LESSER GENERAL PUBLIC LICENSE") && has("Version 2.1") {
        Some("LGPL-2.1-only")
    } else if has("GNU LESSER GENERAL PUBLIC LICENSE") && has("Version 3") {
        Some("LGPL-3.0-only")
    } else if has("GNU GENERAL PUBLIC LICENSE") && has("Version 2,") {
        Some("GPL-2.0-only")
    } else if has("GNU GENERAL PUBLIC LICENSE") && has("Version 3,") {
        Some("GPL-3.0-only")
    } else if has("Mozilla Public License Version 2.0") {
        Some("MPL-2.0")
    } else if has("Permission is hereby granted, free of charge") {
        Some("MIT")
    } else if has("Redistribution and use in source and binary forms") {
        if has("Neither the name")
            || has("may not be used to endorse")
            || has("the names of its contributors")
        {
            Some("BSD-3-Clause")
        } else {
            Some("BSD-2-Clause")
        }
    } else if has("Permission to use, copy, modify, and/or distribute this software") {
        Some("ISC")
    } else if has("This software is provided 'as-is'") {
        Some("Zlib")
    } else if has("This is free and unencumbered software released into the public domain") {
        Some("Unlicense")
    } else {
        None
    }
}

fn license_file(dir: &Path) -> Option<PathBuf> {
    let rd = std::fs::read_dir(dir).ok()?;
    let mut names: Vec<PathBuf> = rd
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            let n = p
                .file_name()
                .map(|f| f.to_string_lossy().to_uppercase())
                .unwrap_or_default();
            p.is_file()
                && (n.starts_with("LICENSE")
                    || n.starts_with("LICENCE")
                    || n.starts_with("COPYING"))
        })
        .collect();
    names.sort();
    names.into_iter().next()
}

/// The license of the project itself, from a LICENSE/COPYING file at its root.
pub fn project_license(dir: &Path) -> Option<(String, String)> {
    let lf = license_file(dir)?;
    let text = std::fs::read_to_string(&lf).ok()?;
    let l = detect_license(&text)?;
    Some((
        l.to_string(),
        format!(
            "{} (text match)",
            lf.file_name().unwrap_or_default().to_string_lossy()
        ),
    ))
}

fn is_component_root(dir: &Path) -> bool {
    dir.join(".git").exists() || license_file(dir).is_some()
}

fn git_describe(dir: &Path) -> Option<String> {
    let o = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["describe", "--tags", "--always", "--dirty"])
        .output()
        .ok()?;
    if !o.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&o.stdout).trim().to_string()).filter(|s| !s.is_empty())
}

fn git_head(dir: &Path) -> Option<String> {
    let o = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !o.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&o.stdout).trim().to_string()).filter(|s| s.len() == 40)
}

#[derive(Clone, Debug, Default)]
pub struct CcOptions {
    pub project_root: PathBuf,
    pub compile_commands: Option<PathBuf>,
    pub build_log: Option<PathBuf>,
    /// directory the build log's relative paths start from (default: the build
    /// directory in compile_commands.json, else the log's directory)
    pub build_dir: Option<PathBuf>,
    pub link_maps: Vec<PathBuf>,
    /// the artifact: only what its link step pulled in is reported
    pub binary: Option<PathBuf>,
    pub use_dpkg: bool,
}

#[derive(Default)]
struct Group {
    built: bool,
    files: BTreeMap<PathBuf, Role>,
    evidence: BTreeSet<String>,
    members: BTreeSet<String>,
    langs: BTreeSet<Lang>,
}

/// Scan the C/C++ side of the build and add it to the inventory.
pub fn scan(inv: &mut Inventory, opts: &CcOptions) -> Result<()> {
    let root = normalize(&opts.project_root);
    let mut facts: Vec<FileFact> = Vec::new();
    let mut build_dirs: BTreeSet<PathBuf> = BTreeSet::new();
    let mut archives_built: BTreeMap<PathBuf, BTreeSet<String>> = BTreeMap::new();
    let mut db = None;
    if let Some(cc) = &opts.compile_commands {
        let d = read_compile_commands(cc)?;
        build_dirs.extend(d.dirs.iter().cloned());
        if !d.compilers.is_empty() {
            inv.properties.insert(
                "sbom-attest:c-compilers".into(),
                d.compilers.iter().cloned().collect::<Vec<_>>().join(","),
            );
        }
        db = Some(d);
        inv.phases.insert(Phase::Build);
    }
    let mut maps: Vec<(PathBuf, PathBuf)> = opts
        .link_maps
        .iter()
        .map(|m| {
            let dir = opts
                .build_dir
                .clone()
                .unwrap_or_else(|| m.parent().unwrap_or(Path::new(".")).to_path_buf());
            (m.clone(), dir)
        })
        .collect();
    if let Some(log) = &opts.build_log {
        let text =
            std::fs::read_to_string(log).with_context(|| format!("reading {}", log.display()))?;
        let start = opts
            .build_dir
            .clone()
            .or_else(|| build_dirs.iter().next().cloned())
            .unwrap_or_else(|| log.parent().unwrap_or(Path::new(".")).to_path_buf());
        build_dirs.insert(normalize(&start));
        let mut lf = read_build_log(&text, &start);
        if let Some(bin) = &opts.binary {
            let bin = normalize(&std::env::current_dir()?.join(bin));
            match lf.scope_to(&bin) {
                Some(objects) => {
                    if let Some(d) = db.as_mut() {
                        let total = d.facts.iter().filter(|f| f.role == Role::Source).count();
                        d.facts
                            .retain(|f| f.object.as_ref().is_none_or(|o| objects.contains(o)));
                        let kept = d.facts.iter().filter(|f| f.role == Role::Source).count();
                        inv.properties.insert(
                            "sbom-attest:compile-units".into(),
                            format!(
                                "{kept} of {total} in compile_commands.json are linked into the artifact"
                            ),
                        );
                    }
                }
                None => inv.unknowns.push(format!(
                    "no link step for {} in the build log; every compile and link in it is reported",
                    bin.file_name().unwrap_or_default().to_string_lossy()
                )),
            }
        }
        facts.extend(lf.files);
        archives_built = lf.archives;
        for m in lf.map_files {
            if m.0.is_file() && !maps.iter().any(|x| x.0 == m.0) {
                maps.push(m);
            }
        }
        for u in lf.unresolved {
            inv.unknowns.push(format!(
                "library -l{u} named in the build log was not found on this system"
            ));
        }
        inv.phases.insert(Phase::Build);
    }
    if let Some(d) = db {
        facts.extend(d.facts);
    }
    for (m, dir) in &maps {
        let text =
            std::fs::read_to_string(m).with_context(|| format!("reading {}", m.display()))?;
        facts.extend(read_link_map(&text, dir));
        inv.phases.insert(Phase::Build);
    }
    add_facts(
        inv,
        &root,
        facts,
        &archives_built,
        &build_dirs,
        opts.use_dpkg,
    )?;
    Ok(())
}

/// Resolve `dynlib:*` components (from DT_NEEDED) to the component that ships the
/// library: one already in the inventory with that file name (a shared library this
/// build linked, or a package file seen at link time), else the file found on the
/// RUNPATH or in the system library directories, with its owning package.
///
/// `machine` is the artifact's ELF `e_machine` (see [`elf_machine`]). When it is
/// given, a library file built for another machine is not a match, so a binary
/// cross-compiled for ARM is not resolved to the build host's x86_64 libc.
pub fn resolve_needed(
    inv: &mut Inventory,
    root: &Path,
    runpaths: &[PathBuf],
    use_dpkg: bool,
    machine: Option<u16>,
) -> Result<()> {
    let ids: Vec<String> = inv
        .components
        .keys()
        .filter(|k| k.starts_with("dynlib:"))
        .cloned()
        .collect();
    let mut dirs: Vec<PathBuf> = runpaths.to_vec();
    dirs.extend(default_lib_dirs());
    for id in ids {
        let soname = id["dynlib:".len()..].to_string();
        let suffix = format!("/{soname}");
        let existing = inv
            .components
            .values()
            .find(|c| {
                !c.id.starts_with("dynlib:")
                    && (c.name == soname
                        || c.properties
                            .get("sbom-attest:files")
                            .is_some_and(|f| f.split(' ').any(|x| x.ends_with(&suffix))))
            })
            .map(|c| c.id.clone());
        let target = match existing {
            Some(t) => Some(t),
            None => match dirs.iter().map(|d| d.join(&soname)).find(|p| {
                p.is_file()
                    && (machine.is_none() || elf_machine(p).is_none_or(|m| Some(m) == machine))
            }) {
                Some(p) => {
                    let p = normalize(&p);
                    let fact = FileFact {
                        path: p.clone(),
                        role: Role::SharedLib,
                        evidence: "binary:needed".into(),
                        members: BTreeSet::new(),
                        lang: Lang::C,
                        object: None,
                    };
                    let placed = add_facts(
                        inv,
                        &normalize(root),
                        vec![fact],
                        &BTreeMap::new(),
                        &BTreeSet::new(),
                        use_dpkg,
                    )?;
                    placed.get(&p).cloned()
                }
                None => None,
            },
        };
        let Some(target) = target else { continue };
        if target == id {
            continue;
        }
        if let Some(old) = inv.components.remove(&id) {
            if let Some(c) = inv.components.get_mut(&target) {
                c.evidence.extend(old.evidence);
                let entry = c.properties.entry("sbom-attest:soname".into()).or_default();
                if !entry.split(' ').any(|x| x == soname) {
                    if !entry.is_empty() {
                        entry.push(' ');
                    }
                    entry.push_str(&soname);
                }
            }
        }
        for set in inv.deps.values_mut() {
            if set.remove(&id) {
                set.insert(target.clone());
            }
        }
        let root_id = inv.root.id.clone();
        inv.depend(&root_id, &target);
    }
    Ok(())
}

fn add_facts(
    inv: &mut Inventory,
    root: &Path,
    facts: Vec<FileFact>,
    archives_built: &BTreeMap<PathBuf, BTreeSet<String>>,
    build_dirs: &BTreeSet<PathBuf>,
    use_dpkg: bool,
) -> Result<HashMap<PathBuf, String>> {
    let mut placed: HashMap<PathBuf, String> = HashMap::new();
    let in_build = |p: &Path| build_dirs.iter().any(|b| p.starts_with(b));
    let outside: Vec<PathBuf> = facts
        .iter()
        .filter(|f| !f.path.starts_with(root) && !in_build(&f.path))
        .map(|f| f.path.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let owners = if use_dpkg {
        dpkg_owners(&outside)
    } else {
        HashMap::new()
    };

    // group key -> (kind of group, group)
    #[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
    enum Key {
        FirstParty,
        Dir(PathBuf),
        Deb(String),
        File(PathBuf),
        SysInclude(PathBuf),
    }
    let mut groups: BTreeMap<Key, Group> = BTreeMap::new();
    let mut debs: HashMap<String, DebPkg> = HashMap::new();
    let mut root_cache: HashMap<PathBuf, Option<PathBuf>> = HashMap::new();

    for f in facts {
        let key = if in_build(&f.path) && !f.path.starts_with(root) {
            // produced by this build (generated sources, libraries it linked)
            if f.role == Role::StaticLib || f.role == Role::SharedLib {
                Key::File(f.path.clone())
            } else {
                Key::FirstParty
            }
        } else if f.path.starts_with(root) {
            // nearest component root between the file and the project root
            let mut found = None;
            let mut dir = f.path.parent().map(Path::to_path_buf);
            while let Some(d) = dir {
                if d == root || !d.starts_with(root) {
                    break;
                }
                let is_root = root_cache
                    .entry(d.clone())
                    .or_insert_with(|| is_component_root(&d).then(|| d.clone()))
                    .clone();
                if is_root.is_some() {
                    found = Some(d.clone());
                    break;
                }
                dir = d.parent().map(Path::to_path_buf);
            }
            match found {
                Some(d) => Key::Dir(d),
                None if f.role == Role::StaticLib || f.role == Role::SharedLib => {
                    Key::File(f.path.clone())
                }
                None => Key::FirstParty,
            }
        } else if let Some(d) = owners.get(&f.path) {
            let k = format!("{}:{}", d.name, d.arch);
            debs.insert(k.clone(), d.clone());
            Key::Deb(k)
        } else if f.role == Role::StaticLib || f.role == Role::SharedLib {
            Key::File(f.path.clone())
        } else {
            // outside the project, no package manager: nearest marker dir, else the include dir
            let mut found = None;
            let mut dir = f.path.parent().map(Path::to_path_buf);
            while let Some(d) = dir {
                if is_component_root(&d) {
                    found = Some(d.clone());
                    break;
                }
                dir = d.parent().map(Path::to_path_buf);
            }
            match found {
                Some(d) => Key::Dir(d),
                None => Key::SysInclude(f.path.parent().map(Path::to_path_buf).unwrap_or_default()),
            }
        };
        let g = groups.entry(key).or_default();
        g.files.entry(f.path.clone()).or_insert(f.role);
        g.built = g.built || in_build(&f.path);
        g.evidence.insert(f.evidence);
        g.members.extend(f.members);
        if f.lang != Lang::Unknown {
            g.langs.insert(f.lang);
        }
    }

    let (distro, distro_ver) = os_release();
    let root_id = inv.root.id.clone();
    let root_is_c = !inv.root.evidence.iter().any(|e| e.starts_with("cargo"));

    for (key, g) in groups {
        let mut hashed: Vec<(String, String)> = Vec::new();
        let base = match &key {
            Key::Dir(d) => d.clone(),
            _ => root.to_path_buf(),
        };
        for p in g.files.keys() {
            if let Ok(h) = sha256_file(p) {
                let rel = p
                    .strip_prefix(&base)
                    .map(slash)
                    .unwrap_or_else(|_| display_path(p, root));
                hashed.push((rel, h));
            }
        }
        let lang = if g.langs.contains(&Lang::Cpp) {
            Lang::Cpp
        } else if g.langs.contains(&Lang::C) {
            Lang::C
        } else if g.langs.contains(&Lang::Asm) {
            Lang::Asm
        } else {
            Lang::C
        };
        let files_prop = {
            let mut v: Vec<String> = g.files.keys().map(|p| display_path(p, root)).collect();
            v.sort();
            v
        };
        let mut c = match &key {
            Key::FirstParty => {
                if root_is_c {
                    let mut c = inv.root.clone();
                    c.evidence.clear();
                    c.properties.clear();
                    c.hashes.clear();
                    c.hash_subject = None;
                    c
                } else {
                    let name = format!("{}-native", inv.root.name);
                    let mut c = Component::new(format!("src:{name}"), Kind::Library, name);
                    c.version = inv.root.version.clone();
                    c.description =
                        Some("First-party C/C++ sources compiled into the artifact".into());
                    c
                }
            }
            Key::Dir(d) => {
                let name = d
                    .file_name()
                    .map(|f| f.to_string_lossy().to_string())
                    .unwrap_or_default();
                let mut c = Component::new(
                    format!("src:{}", display_path(d, root)),
                    Kind::Library,
                    name,
                );
                c.version = git_describe(d);
                if let Some(lf) = license_file(d) {
                    if let Ok(t) = std::fs::read_to_string(&lf) {
                        if let Some(l) = detect_license(&t) {
                            c.license = Some(l.into());
                            c.properties.insert(
                                "sbom-attest:license-detected-from".into(),
                                format!("{} (text match)", display_path(&lf, root)),
                            );
                        }
                    }
                }
                if let Some(head) = git_head(d) {
                    c.properties.insert("sbom-attest:git-commit".into(), head);
                }
                c.properties
                    .insert("sbom-attest:path".into(), display_path(d, root));
                c
            }
            Key::Deb(k) => {
                let d = &debs[k];
                let mut c = Component::new(
                    format!("deb:{}@{}:{}", d.name, d.version, d.arch),
                    Kind::Library,
                    &d.name,
                );
                c.version = Some(d.version.clone());
                let ns = if distro.is_empty() {
                    "debian".to_string()
                } else {
                    distro.clone()
                };
                let mut q = format!("?arch={}", purl_escape(&d.arch));
                if !distro_ver.is_empty() {
                    q.push_str(&format!(
                        "&distro={}-{}",
                        purl_escape(&ns),
                        purl_escape(&distro_ver)
                    ));
                }
                c.purl = Some(format!(
                    "pkg:deb/{}/{}@{}{}",
                    ns,
                    purl_escape(&d.name),
                    purl_escape(&d.version),
                    q
                ));
                c.producer = d.maintainer.clone();
                c.license = d.license.clone();
                if let Some(h) = &d.homepage {
                    c.external_refs.push(("website".into(), h.clone()));
                }
                c.evidence.insert("dpkg".into());
                c
            }
            Key::File(p) => {
                let name = p
                    .file_name()
                    .map(|f| f.to_string_lossy().to_string())
                    .unwrap_or_default();
                let mut c = Component::new(
                    format!("file:{}", display_path(p, root)),
                    Kind::Library,
                    name,
                );
                c.properties
                    .insert("sbom-attest:path".into(), display_path(p, root));
                if g.built {
                    // built here from first-party sources: same version, producer, license
                    c.version = inv.root.version.clone();
                    c.producer = inv.root.producer.clone();
                    c.license = inv.root.license.clone();
                    c.properties
                        .insert("sbom-attest:built-by-this-build".into(), "true".into());
                }
                c
            }
            Key::SysInclude(d) => {
                let mut c = Component::new(
                    format!("include:{}", display_path(d, root)),
                    Kind::Library,
                    display_path(d, root),
                );
                c.description = Some("System headers with no package owner found".into());
                c
            }
        };
        c.lang = lang;
        c.evidence.extend(g.evidence.iter().cloned());
        let libs: Vec<&PathBuf> = g
            .files
            .iter()
            .filter(|(_, r)| matches!(r, Role::StaticLib | Role::SharedLib))
            .map(|(p, _)| p)
            .collect();
        if libs.len() == 1 && g.files.len() == 1 {
            // a single library file: hash the file itself
            if let Ok(h) = sha256_file(libs[0]) {
                c.hashes.push(("SHA-256".into(), h));
                let subject = if g.files.values().next() == Some(&Role::StaticLib) {
                    "archive"
                } else {
                    "shared-object"
                };
                c.hash_subject = Some(subject.into());
            }
            let role = g.files.values().next().copied();
            c.properties.insert(
                "sbom-attest:linkage".into(),
                if role == Some(Role::StaticLib) {
                    "static"
                } else {
                    "dynamic"
                }
                .into(),
            );
            if let Some(objs) = archives_built.get(libs[0]) {
                c.properties.insert(
                    "sbom-attest:archive-built-from".into(),
                    objs.iter().cloned().collect::<Vec<_>>().join(" "),
                );
                c.properties
                    .insert("sbom-attest:built-by-this-build".into(), "true".into());
            }
        } else if !hashed.is_empty() {
            c.hashes.push(("SHA-256".into(), tree_digest(&hashed)));
            let all_source = g
                .files
                .values()
                .all(|r| matches!(r, Role::Source | Role::Header));
            c.hash_subject = Some(if all_source { "source-files" } else { "files" }.into());
            c.properties
                .insert("sbom-attest:file-count".into(), hashed.len().to_string());
        }
        if !g.members.is_empty() {
            c.properties.insert(
                "sbom-attest:linked-members".into(),
                g.members.iter().cloned().collect::<Vec<_>>().join(" "),
            );
        }
        if files_prop.len() <= 200 {
            c.properties
                .insert("sbom-attest:files".into(), files_prop.join(" "));
        }
        c.scope = Scope::Required;
        let id = if matches!(key, Key::FirstParty) && root_is_c {
            root_id.clone()
        } else {
            c.id.clone()
        };
        for p in g.files.keys() {
            placed.insert(p.clone(), id.clone());
        }
        if id == root_id {
            inv.root.absorb(c);
        } else {
            inv.add(c);
            inv.depend(&root_id, &id);
        }
    }
    Ok(placed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn elf_header(machine: u16) -> Vec<u8> {
        let mut h = vec![0u8; 64];
        h[..4].copy_from_slice(b"ELF");
        h[4] = 2; // 64-bit
        h[5] = 1; // little endian
        h[18..20].copy_from_slice(&machine.to_le_bytes());
        h
    }

    #[test]
    fn needed_library_must_match_the_artifact_machine() {
        let dir = std::env::temp_dir().join(format!("sbom-attest-needed-{}", std::process::id()));
        let (x86, arm) = (dir.join("x86"), dir.join("arm"));
        std::fs::create_dir_all(&x86).unwrap();
        std::fs::create_dir_all(&arm).unwrap();
        std::fs::write(x86.join("libdemo.so.1"), elf_header(62)).unwrap(); // EM_X86_64
        std::fs::write(arm.join("libdemo.so.1"), elf_header(40)).unwrap(); // EM_ARM
        assert_eq!(elf_machine(&x86.join("libdemo.so.1")), Some(62));
        assert_eq!(elf_machine(&dir), None);

        let resolve = |machine: Option<u16>| {
            let root = Component::new("root", Kind::Application, "app");
            let mut inv = Inventory::new(root, "1970-01-01T00:00:00Z".into());
            inv.add(Component::new(
                "dynlib:libdemo.so.1",
                Kind::Library,
                "libdemo.so.1",
            ));
            resolve_needed(&mut inv, &dir, &[x86.clone(), arm.clone()], false, machine).unwrap();
            inv.components
                .values()
                .filter_map(|c| c.properties.get("sbom-attest:path").cloned())
                .collect::<Vec<_>>()
        };
        // An ARM binary skips the x86_64 library that comes first on the search path.
        let arm_paths = resolve(Some(40));
        assert_eq!(arm_paths.len(), 1, "{arm_paths:?}");
        assert!(arm_paths[0].contains("arm"), "{arm_paths:?}");
        // Unknown machine keeps the old first-match behaviour.
        let any = resolve(None);
        assert!(any.len() == 1 && any[0].contains("x86"), "{any:?}");
        // No library of the right machine: the soname stays unresolved.
        let none = resolve(Some(183)); // EM_AARCH64
        assert!(none.is_empty(), "{none:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn splits_shell() {
        assert_eq!(
            shell_split(r#"cc -DX="a b" 'q r' a\ b -c x.c"#),
            vec!["cc", "-DX=a b", "q r", "a b", "-c", "x.c"]
        );
        assert_eq!(shell_split(r#"cc -DS=\"v\""#), vec!["cc", r#"-DS="v""#]);
    }

    #[test]
    fn depfile() {
        let d = "obj/a.o: ../src/a.c ../inc/a.h \\\n /usr/include/stdio.h \\\n  my\\ dir/x.h\n";
        assert_eq!(
            parse_depfile(d),
            vec![
                "../src/a.c",
                "../inc/a.h",
                "/usr/include/stdio.h",
                "my dir/x.h"
            ]
        );
    }

    #[test]
    fn build_log_links_and_archives() {
        let log = "[1/3] /usr/bin/cc -O2 -c ../a.c -o a.o\n[2/3] : && /usr/bin/ar qc libx.a a.o b.o && /usr/bin/ranlib libx.a && :\n[3/3] : && /usr/bin/cc -O2 main.o -o app libx.a -L/nonexistent -lm -lnosuchlib -Wl,-Map=app.map && :\n";
        let f = read_build_log(log, Path::new("/b"));
        let archive = f.archives.get(Path::new("/b/libx.a")).unwrap();
        assert!(archive.contains("a.o") && archive.contains("b.o"));
        assert!(f
            .files
            .iter()
            .any(|x| x.path == Path::new("/b/libx.a") && x.role == Role::StaticLib));
        assert_eq!(
            f.map_files,
            vec![(PathBuf::from("/b/app.map"), PathBuf::from("/b"))]
        );
        assert!(f.unresolved.contains("nosuchlib"));
    }

    #[test]
    fn ninja_deps_table() {
        let t = "a/x.c.o: #deps 3, deps mtime 1 (VALID)
    /src/x.c
    /src/x.h
    ../inc/y.h

b.o: #deps 1, deps mtime 1 (STALE)
    /src/b.c
";
        let m = parse_ninja_deps(t, Path::new("/build"));
        let x = &m[Path::new("/build/a/x.c.o")];
        assert_eq!(x.len(), 3);
        assert_eq!(x[2], PathBuf::from("/inc/y.h"));
        assert_eq!(m[Path::new("/build/b.o")].len(), 1);
    }

    #[test]
    fn scope_follows_the_artifact() {
        let log = "cc -c a.c -o a.o
cc -c b.c -o b.o
cc -c t.c -o t.o
ar qc libb.a b.o
cc -shared -o libs.so s.o
cc a.o -o app libb.a libs.so
cc t.o -o other
";
        let mut f = read_build_log(log, Path::new("/b"));
        assert_eq!(f.links.len(), 3);
        let objs = f.scope_to(Path::new("/b/app")).unwrap();
        assert!(objs.contains(Path::new("/b/a.o")));
        assert!(objs.contains(Path::new("/b/b.o")), "archive member");
        assert!(
            objs.contains(Path::new("/b/s.o")),
            "shared library built here"
        );
        assert!(!objs.contains(Path::new("/b/t.o")), "another executable");
        assert!(f.scope_to(Path::new("/b/missing")).is_none());
    }

    #[test]
    fn tool_names() {
        assert!(is_tool("/usr/bin/arm-none-eabi-gcc", COMPILERS));
        assert!(is_tool("gcc-13", COMPILERS));
        assert!(is_tool("C:/x/clang++.exe", COMPILERS));
        assert!(!is_tool("/usr/bin/cmake", COMPILERS));
        assert!(is_tool("/usr/bin/ar", ARCHIVERS));
        assert!(!is_tool("/usr/bin/ranlib", ARCHIVERS));
    }

    #[test]
    fn gnu_ld_map() {
        let map = "Archive member included to satisfy reference by file (symbol)\n\n/usr/lib/x86_64-linux-gnu/libc_nonshared.a(atexit.oS)\n                              main.o (atexit)\nlibodid.a(opendroneid.c.o)\n                              main.o (odid_encodeBasicIDMessage)\n\nLOAD main.o\nLOAD libodid.a\nLOAD /usr/lib/x86_64-linux-gnu/libm.so\n";
        let f = read_link_map(map, Path::new("/b"));
        let odid = f
            .iter()
            .find(|x| x.path == Path::new("/b/libodid.a"))
            .unwrap();
        assert!(odid.members.contains("opendroneid.c.o"));
        assert!(f
            .iter()
            .any(|x| x.path == Path::new("/usr/lib/x86_64-linux-gnu/libm.so")
                && x.role == Role::SharedLib));
        assert!(f
            .iter()
            .any(|x| x.path == Path::new("/usr/lib/x86_64-linux-gnu/libc_nonshared.a")));
    }

    #[test]
    fn lld_map() {
        let map = "             VMA              LMA     Size Align Out     In      Symbol\n           201120           201120       2a    16         libfw.a(crc.o):(.text.crc16)\n";
        let f = read_link_map(map, Path::new("/b"));
        assert_eq!(f.len(), 1);
        assert!(f[0].members.contains("crc.o"));
    }

    #[test]
    fn licenses() {
        assert_eq!(
            detect_license("Apache License\nVersion 2.0, January 2004"),
            Some("Apache-2.0")
        );
        assert_eq!(
            detect_license(
                "Redistribution and use in source and binary forms ... Neither the name of"
            ),
            Some("BSD-3-Clause")
        );
        assert_eq!(
            detect_license("Permission is hereby granted, free of charge, to any"),
            Some("MIT")
        );
        assert_eq!(detect_license("all rights reserved"), None);
    }
}
