"""Differential comparison of sbom-attest output with reference tools.

  compare.py rust <cargo-cyclonedx.json> <sbom-attest.cdx.json>
  compare.py c <syft-dir.json> <syft-bin.json> <sbom-attest.cdx.json>
  compare.py hashes <a.cdx.json> <b.cdx.json>     (exit 1 if component hashes differ)
"""
import json
import sys


def load(p):
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def comps(doc):
    out = []

    def walk(cs):
        for c in cs or []:
            out.append(c)
            walk(c.get("components"))

    walk(doc.get("components"))
    return out


def nv(c):
    return (c.get("name", "").replace("_", "-").lower(), c.get("version", ""))


def rust(ref_path, ours_path):
    ref, ours = load(ref_path), load(ours_path)
    root = ref.get("metadata", {}).get("component", {}).get("name")
    r = {nv(c) for c in comps(ref) if c.get("name") != root}
    o = {nv(c) for c in comps(ours)}
    name = ours.get("metadata", {}).get("component", {}).get("name")
    only_ref, only_ours = sorted(r - o), sorted(o - r)
    # hashes for the matched crates
    rh = {nv(c): {h["alg"]: h["content"] for h in c.get("hashes", [])} for c in comps(ref)}
    oh = {nv(c): {h["alg"]: h["content"] for h in c.get("hashes", [])} for c in comps(ours)}
    hash_diff = [k for k in r & o if rh.get(k, {}).get("SHA-256") and oh.get(k, {}).get("SHA-256")
                 and rh[k]["SHA-256"] != oh[k]["SHA-256"]]
    print(f"{name}: cargo-cyclonedx {len(r)} components, sbom-attest {len(o)}, common {len(r & o)}, "
          f"only cargo-cyclonedx {len(only_ref)}, only sbom-attest {len(only_ours)}, crate hash mismatches {len(hash_diff)}")
    for k in only_ref:
        print(f"  only cargo-cyclonedx: {k[0]} {k[1]}")
    for k in only_ours:
        print(f"  only sbom-attest: {k[0]} {k[1]}")


def c(syft_dir, syft_bin, ours_path):
    try:
        sd = comps(load(syft_dir))
    except Exception:
        sd = []
    try:
        sb = comps(load(syft_bin))
    except Exception:
        sb = []
    ours = comps(load(ours_path))
    def show(label, cs):
        kinds = {}
        for x in cs:
            kinds.setdefault(x.get("type", "?"), []).append(x.get("name", "?"))
        print(f"{label}: {len(cs)} components " + "; ".join(f"{k}={sorted(set(v))[:12]}" for k, v in sorted(kinds.items())))
    show("syft dir:opendroneid-core-c", sd)
    show("syft file:<test binary>", sb)
    show("sbom-attest (compile_commands + build log + map + binary)", ours)
    syft_names = {x.get("name", "").lower() for x in sd + sb}
    missed = sorted({x.get("name") for x in ours} - {n for n in syft_names})
    print(f"  components sbom-attest found that syft did not: {len(missed)}: {missed[:30]}")


def hashes(a, b):
    def table(p):
        d = load(p)
        t = {}
        for x in comps(d):
            t[x.get("bom-ref")] = tuple(sorted((h["alg"], h["content"]) for h in x.get("hashes", [])))
        root = d["metadata"]["component"]
        t["<root>"] = tuple(sorted((h["alg"], h["content"]) for h in root.get("hashes", [])))
        return t
    ta, tb = table(a), table(b)
    diff = sorted(k for k in set(ta) | set(tb) if ta.get(k) != tb.get(k))
    hashed = sum(1 for v in ta.values() if v)
    print(f"{len(ta)} components ({hashed} hashed, root included); differing: {len(diff)}")
    for k in diff:
        print(f"  differs: {k}: {ta.get(k)} vs {tb.get(k)}")
    return 1 if diff else 0


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "rust":
        rust(sys.argv[2], sys.argv[3])
    elif mode == "c":
        c(sys.argv[2], sys.argv[3], sys.argv[4])
    elif mode == "hashes":
        sys.exit(hashes(sys.argv[2], sys.argv[3]))
