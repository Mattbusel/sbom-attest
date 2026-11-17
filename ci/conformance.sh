#!/usr/bin/env bash
# Conformance and differential tests against public references (Linux x86_64).
#
#  1. schema:   every CycloneDX output validates against the official CycloneDX 1.6 JSON
#               schema and with `cyclonedx validate`; every SPDX output with pyspdxtools
#  2. score:    sbomqs scores each SBOM; the run fails below SBOMQS_MIN
#  3. diff:     Rust components vs cargo-cyclonedx 0.5.10 on our crates; C components vs
#               syft on an opendroneid-core-c build
#  4. repro:    two clean builds of opendroneid-core-c give identical component hashes
#  5. verify:   signatures and attestations verify with cosign
#
# Usage: ci/conformance.sh [workdir]. Results land in <workdir>/results.
# Needs: cargo, cmake, ninja, gcc, python3-venv, curl, and libgtest-dev (opendroneid-core-c tests).
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${1:-/tmp/sbom-attest-ci}"
TOOLS="$WORK/tools"
RES="$WORK/results"
SUBJ="$WORK/subjects"
# gate on sbomqs' CISA 2026 minimum elements profile ("ntia"); the overall score is recorded
SBOMQS_MIN="${SBOMQS_MIN:-9.0}"
export SOURCE_DATE_EPOCH=1763337600
mkdir -p "$TOOLS" "$RES" "$SUBJ"
export PATH="$TOOLS:$PATH"

CYCLONEDX_CLI=v0.33.1
SBOMQS=2.1.3
SYFT=1.56.0
COSIGN=v3.1.4
CARGO_CYCLONEDX=0.5.10
SPEC_REF=1.7.2
ODID_COMMIT=849c03adbe0cdd68997a462fafab397edcfe53f3
ODID_PRODUCER="Open Drone ID project"

log() { printf '\n== %s\n' "$*"; }
fetch() { [ -s "$2" ] || curl -fsSL --retry 3 -o "$2" "$1"; }

log "tools"
fetch "https://github.com/CycloneDX/cyclonedx-cli/releases/download/$CYCLONEDX_CLI/cyclonedx-linux-x64" "$TOOLS/cyclonedx"
fetch "https://github.com/sigstore/cosign/releases/download/$COSIGN/cosign-linux-amd64" "$TOOLS/cosign"
chmod +x "$TOOLS/cyclonedx" "$TOOLS/cosign"
if [ ! -x "$TOOLS/sbomqs" ]; then
  fetch "https://github.com/interlynk-io/sbomqs/releases/download/v$SBOMQS/sbomqs_${SBOMQS}_Linux_x86_64.tar.gz" "$TOOLS/sbomqs.tgz"
  tar -xzf "$TOOLS/sbomqs.tgz" -C "$TOOLS" sbomqs
fi
if [ ! -x "$TOOLS/syft" ]; then
  fetch "https://github.com/anchore/syft/releases/download/v$SYFT/syft_${SYFT}_linux_amd64.tar.gz" "$TOOLS/syft.tgz"
  tar -xzf "$TOOLS/syft.tgz" -C "$TOOLS" syft
fi
if [ ! -x "$TOOLS/cargo-cyclonedx" ]; then
  fetch "https://github.com/CycloneDX/cyclonedx-rust-cargo/releases/download/cargo-cyclonedx-$CARGO_CYCLONEDX/cargo-cyclonedx-x86_64-unknown-linux-gnu.tar.xz" "$TOOLS/ccdx.txz"
  tar -xJf "$TOOLS/ccdx.txz" -C "$TOOLS" --strip-components=1 --wildcards '*/cargo-cyclonedx'
fi
mkdir -p "$TOOLS/schema"
for s in bom-1.6.schema.json spdx.schema.json jsf-0.82.schema.json cryptography-defs.schema.json; do
  fetch "https://raw.githubusercontent.com/CycloneDX/specification/$SPEC_REF/schema/$s" "$TOOLS/schema/$s" || true
done
if [ ! -x "$TOOLS/venv/bin/pyspdxtools" ]; then
  python3 -m venv "$TOOLS/venv"
  "$TOOLS/venv/bin/pip" -q install "jsonschema==4.23.0" "referencing==0.35.1" "spdx-tools==0.8.3" "rfc3987==1.3.8"
fi
PY="$TOOLS/venv/bin/python"
{ cyclonedx --version; sbomqs version 2>/dev/null | head -3; syft version | head -2; cosign version 2>/dev/null | grep GitVersion; cargo-cyclonedx cyclonedx --version; } > "$RES/tool-versions.txt" 2>&1 || true

log "build sbom-attest"
( cd "$HERE" && cargo build --release --locked -q )
SA="${CARGO_TARGET_DIR:-$HERE/target}/release/sbom-attest"
"$SA" --version | tee "$RES/sbom-attest-version.txt"
KEYDIR="$WORK/keys"; mkdir -p "$KEYDIR"
[ -f "$KEYDIR/ci.key" ] || "$SA" keygen --out "$KEYDIR/ci"

FAIL=0
validate() { # $1 = cdx, $2 = spdx (optional)
  local cdx="$1" spdx="${2:-}"
  local ncomp; ncomp=$("$PY" -c 'import json,sys; print(len(json.load(open(sys.argv[1])).get("components",[])))' "$cdx")
  if "$PY" "$HERE/ci/validate_cdx.py" "$TOOLS/schema" "$cdx" >> "$RES/schema.txt" 2>&1; then
    echo "PASS schema   $(basename "$cdx")" | tee -a "$RES/summary.txt"
  else
    echo "FAIL schema   $(basename "$cdx")" | tee -a "$RES/summary.txt"; FAIL=1
  fi
  if cyclonedx validate --input-file "$cdx" --input-format json --input-version v1_6 --fail-on-errors >> "$RES/cyclonedx-cli.txt" 2>&1; then
    echo "PASS cdx-cli  $(basename "$cdx")" | tee -a "$RES/summary.txt"
  else
    echo "FAIL cdx-cli  $(basename "$cdx")" | tee -a "$RES/summary.txt"; FAIL=1
  fi
  if [ -n "$spdx" ]; then
    if "$TOOLS/venv/bin/pyspdxtools" -i "$spdx" >> "$RES/pyspdxtools.txt" 2>&1; then
      echo "PASS spdx     $(basename "$spdx")" | tee -a "$RES/summary.txt"
    else
      echo "FAIL spdx     $(basename "$spdx")" | tee -a "$RES/summary.txt"; FAIL=1
    fi
  fi
  local score
  score=$(sbomqs score --profile ntia "$cdx" --json 2>/dev/null | "$PY" -c 'import json,sys; f=json.load(sys.stdin)["files"][0]; print(f["profiles"][0]["score"] if f.get("profiles") else f["sbom_quality_score"])' || echo 0)
  overall=$(sbomqs score "$cdx" --json 2>/dev/null | "$PY" -c 'import json,sys; print(round(json.load(sys.stdin)["files"][0]["sbom_quality_score"],2))' || echo 0)
  echo "$(basename "$cdx") cisa-2026=$score overall=$overall" >> "$RES/sbomqs.txt"
  if [ "$ncomp" = 0 ]; then
    echo "INFO sbomqs   $(basename "$cdx") $score (no dependencies: relationship element not applicable, not gated)" | tee -a "$RES/summary.txt"
  elif "$PY" -c "import sys; sys.exit(0 if float('$score') >= float('$SBOMQS_MIN') else 1)"; then
    echo "PASS sbomqs   $(basename "$cdx") $score >= $SBOMQS_MIN" | tee -a "$RES/summary.txt"
  else
    echo "FAIL sbomqs   $(basename "$cdx") $score < $SBOMQS_MIN" | tee -a "$RES/summary.txt"; FAIL=1
  fi
}
: > "$RES/summary.txt"

log "rust subjects vs cargo-cyclonedx $CARGO_CYCLONEDX"
for c in remoteid misb uas-cot mavlink-tlog; do
  [ -d "$SUBJ/$c" ] || git clone -q --depth 1 -c core.autocrlf=false "https://github.com/Mattbusel/$c" "$SUBJ/$c"
done
rm -rf "$SUBJ/sbom-attest"; mkdir -p "$SUBJ/sbom-attest"
cp -r "$HERE/src" "$HERE/Cargo.toml" "$HERE/Cargo.lock" "$HERE/README.md" "$SUBJ/sbom-attest/" 2>/dev/null || cp -r "$HERE/src" "$HERE/Cargo.toml" "$HERE/Cargo.lock" "$SUBJ/sbom-attest/"
for c in remoteid misb uas-cot mavlink-tlog sbom-attest; do
  d="$SUBJ/$c"; ( cd "$d" && cargo generate-lockfile -q 2>/dev/null || true )
  "$SA" generate --manifest-path "$d/Cargo.toml" --target x86_64-unknown-linux-gnu --author "Tensorust LLC" \
    --key "$KEYDIR/ci.key" --cdx "$RES/$c.cdx.json" --spdx "$RES/$c.spdx.json" 2>>"$RES/generate.txt"
  ( cd "$d" && cargo-cyclonedx cyclonedx --format json --spec-version 1.6 --target x86_64-unknown-linux-gnu --override-filename "ref" -q 2>>"$RES/generate.txt" ) || true
  ref=$(find "$d" -maxdepth 1 -name 'ref.json' -o -maxdepth 1 -name 'ref.cdx.json' | head -1)
  validate "$RES/$c.cdx.json" "$RES/$c.spdx.json"
  if [ -n "$ref" ]; then
    cp "$ref" "$RES/$c.cargo-cyclonedx.json"
    "$PY" "$HERE/ci/compare.py" rust "$RES/$c.cargo-cyclonedx.json" "$RES/$c.cdx.json" | tee -a "$RES/differential.txt"
  else
    echo "$c: cargo-cyclonedx produced no file" | tee -a "$RES/differential.txt"
  fi
done

log "target-conditional features fixture (rust-lang/cargo#9863)"
fx="$HERE/tests/fixtures/target-cfg-features/app"
"$SA" generate --manifest-path "$fx/Cargo.toml" --offline --target x86_64-unknown-linux-musl --cdx "$RES/fixture-musl.cdx.json" 2>>"$RES/generate.txt"
rm -rf "$WORK/fixture" && cp -r "$HERE/tests/fixtures/target-cfg-features" "$WORK/fixture"
( cd "$WORK/fixture/app" && cargo-cyclonedx cyclonedx --format json --spec-version 1.6 --target x86_64-unknown-linux-musl --override-filename ref -q ) || true
"$PY" "$HERE/ci/compare.py" rust "$WORK/fixture/app/ref.json" "$RES/fixture-musl.cdx.json" | sed 's/^/fixture musl: /' | tee -a "$RES/differential.txt"

log "opendroneid-core-c: two clean builds"
ODID="$SUBJ/opendroneid-core-c"
if [ ! -d "$ODID" ]; then
  git clone -q -c core.autocrlf=false https://github.com/opendroneid/opendroneid-core-c "$ODID"
  git -C "$ODID" checkout -q "$ODID_COMMIT"
fi
git -C "$ODID" submodule update -q --init --depth 1
build_odid() { # $1 = build dir
  rm -rf "$1"
  cmake -S "$ODID" -B "$1" -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_WIFI=OFF -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    -DCMAKE_C_FLAGS="-ffile-prefix-map=$ODID=. -ffile-prefix-map=$1=build" \
    -DCMAKE_C_LINK_EXECUTABLE="<CMAKE_C_COMPILER> <FLAGS> <CMAKE_C_LINK_FLAGS> <LINK_FLAGS> <OBJECTS> -o <TARGET> -Wl,-Map=<TARGET>.map <LINK_LIBRARIES>" \
    > "$1.cmake.log"
  ninja -C "$1" -v > "$1.build.log"
}
for i in 1 2; do
  B="$WORK/odid-build"
  build_odid "$B"
  bin="$B/test/odidtest"
  # the link line writes odid.map, and the build log names it, so no --link-map is needed
  "$SA" generate --no-cargo --project-root "$ODID" --compile-commands "$B/compile_commands.json" \
    --build-log "$B.build.log" --binary "$bin" --name opendroneid-core-c --producer "$ODID_PRODUCER" \
    --author "Tensorust LLC" --memsafe --key "$KEYDIR/ci.key" \
    --cdx "$RES/odid-$i.cdx.json" --spdx "$RES/odid-$i.spdx.json" 2>>"$RES/generate.txt"
  cp "$bin" "$WORK/odid-bin-$i"
done
validate "$RES/odid-1.cdx.json" "$RES/odid-1.spdx.json"
if "$PY" "$HERE/ci/compare.py" hashes "$RES/odid-1.cdx.json" "$RES/odid-2.cdx.json" | tee "$RES/reproducibility.txt"; then
  echo "PASS repro    opendroneid-core-c component hashes identical across clean builds" | tee -a "$RES/summary.txt"
else
  echo "FAIL repro    opendroneid-core-c" | tee -a "$RES/summary.txt"; FAIL=1
fi

log "syft on the same build"
syft scan "dir:$ODID" -q -o "cyclonedx-json=$RES/odid.syft-dir.cdx.json" || true
syft scan "file:$WORK/odid-bin-1" -q -o "cyclonedx-json=$RES/odid.syft-bin.cdx.json" || true
"$PY" "$HERE/ci/compare.py" c "$RES/odid.syft-dir.cdx.json" "$RES/odid.syft-bin.cdx.json" "$RES/odid-1.cdx.json" | tee -a "$RES/differential.txt"

log "evidence bundle and cosign verification"
rm -rf "$RES/bundle"
"$SA" bundle --no-cargo --project-root "$ODID" --compile-commands "$WORK/odid-build/compile_commands.json" \
  --build-log "$WORK/odid-build.build.log" --binary "$WORK/odid-build/test/odidtest" --name opendroneid-core-c \
  --producer "$ODID_PRODUCER" --author "Tensorust LLC" \
  --memsafe --key "$KEYDIR/ci.key" --out "$RES/bundle" --vendor-sbom "$RES/odid.syft-dir.cdx.json" 2>>"$RES/generate.txt"
( cd "$RES/bundle" && sha256sum -c --quiet SHA256SUMS ) && echo "PASS sums     bundle SHA256SUMS" | tee -a "$RES/summary.txt"
check_cmd() { # label, command...
  local label="$1"; shift
  if "$@" >> "$RES/verify.txt" 2>&1; then echo "PASS $label" | tee -a "$RES/summary.txt"; else echo "FAIL $label" | tee -a "$RES/summary.txt"; FAIL=1; fi
}
P="$RES/bundle/signing-key.pub"
check_cmd "cosign verify-blob sbom.cdx.json" cosign verify-blob --key "$P" --signature "$RES/bundle/sbom.cdx.json.sig" --insecure-ignore-tlog=true "$RES/bundle/sbom.cdx.json"
check_cmd "cosign verify-blob sbom.spdx.json" cosign verify-blob --key "$P" --signature "$RES/bundle/sbom.spdx.json.sig" --insecure-ignore-tlog=true "$RES/bundle/sbom.spdx.json"
check_cmd "cosign verify-blob index.json" cosign verify-blob --key "$P" --signature "$RES/bundle/index.json.sig" --insecure-ignore-tlog=true "$RES/bundle/index.json"
check_cmd "cosign verify-blob-attestation slsaprovenance1" cosign verify-blob-attestation --key "$P" --signature "$RES/bundle/provenance.intoto.json" --type slsaprovenance1 --insecure-ignore-tlog=true "$WORK/odid-build/test/odidtest"
check_cmd "cosign verify-blob-attestation cyclonedx" cosign verify-blob-attestation --key "$P" --signature "$RES/bundle/sbom.intoto.json" --type cyclonedx --insecure-ignore-tlog=true "$WORK/odid-build/test/odidtest"
check_cmd "sbom-attest verify-sbom (JSF)" "$SA" verify-sbom --pub "$P" "$RES/bundle/sbom.cdx.json"
printf 'tampered' > "$WORK/tampered.bin"
if cosign verify-blob-attestation --key "$P" --signature "$RES/bundle/provenance.intoto.json" --type slsaprovenance1 --insecure-ignore-tlog=true "$WORK/tampered.bin" >> "$RES/verify.txt" 2>&1; then
  echo "FAIL negative: cosign accepted a different artifact" | tee -a "$RES/summary.txt"; FAIL=1
else
  echo "PASS negative: cosign rejects the attestation for a different artifact" | tee -a "$RES/summary.txt"
fi
validate "$RES/bundle/sbom.cdx.json" "$RES/bundle/sbom.spdx.json"

log "summary"
cat "$RES/summary.txt"
exit $FAIL
