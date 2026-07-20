#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

# local-IS-5: fresh-clone-style path without GitHub.
# Producer binary and verifier binary are built in SEPARATE target dirs.
# Label: local-IS-5 (not remote IS-5).

WORK="$(mktemp -d "${TMPDIR:-/tmp}/lia-local-is5-XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

PROD_TARGET="$WORK/target-prod"
VERIFY_TARGET="$WORK/target-verify"
SAMPLE="$WORK/sample"
BUNDLE="$WORK/bundle"
EVIDENCE="$WORK/evidence"
SECRET="$(python3 -c 'print("66"*32)')"

mkdir -p "$SAMPLE" "$EVIDENCE" "$BUNDLE"
echo "base" >"$SAMPLE/readme.txt"
(
  cd "$SAMPLE"
  git init -q
  git config user.email "local-is5@lia.local"
  git config user.name "local-is5"
  git add readme.txt
  git commit -q -m "base"
  echo "head change" >>readme.txt
  git add readme.txt
  git commit -q -m "head"
)
echo "supplied-evidence" >"$EVIDENCE/note.txt"
BASE="$(cd "$SAMPLE" && git rev-parse HEAD~1)"
HEAD="$(cd "$SAMPLE" && git rev-parse HEAD)"

echo "== local-IS-5 producer build (separate target) =="
CARGO_TARGET_DIR="$PROD_TARGET" cargo build -p lia-cli --release --manifest-path "$ROOT/Cargo.toml"
PROD_LIA="$PROD_TARGET/release/lia"
test -x "$PROD_LIA"

echo "== local-IS-5 action entrypoint (AUDIT verify-run) =="
export LIA_REPO="$SAMPLE"
export LIA_BASE="$BASE"
export LIA_HEAD="$HEAD"
export LIA_EVIDENCE="$EVIDENCE"
export LIA_OUT="$BUNDLE"
export LIA_SECRET_KEY_HEX="$SECRET"
export LIA_BIN="$PROD_LIA"
export OUT="$BUNDLE"
bash "$ROOT/.github/actions/lia-trust/entrypoint.sh"
test -f "$BUNDLE/MANIFEST.json"
python3 - <<PY
import json
m=json.load(open("$BUNDLE/MANIFEST.json"))
assert m.get("assurance_level")=="AUDIT", m
assert m.get("mode")=="verify-run", m
meta=json.load(open("$BUNDLE/audit-meta.json"))
assert meta["prevention"] is False
assert "AUDIT" in meta["label"]
print("producer bundle AUDIT ok")
PY

echo "== local-IS-5 verifier build (separate target, separate binary) =="
CARGO_TARGET_DIR="$VERIFY_TARGET" cargo build -p lia-cli --release --manifest-path "$ROOT/Cargo.toml"
VERIFY_LIA="$VERIFY_TARGET/release/lia"
test -x "$VERIFY_LIA"
test "$(realpath "$PROD_LIA")" != "$(realpath "$VERIFY_LIA")"

echo "== local-IS-5 verify with separately-built binary =="
set +e
"$VERIFY_LIA" verify "$BUNDLE" >"$WORK/verify.out" 2>"$WORK/verify.err"
VE=$?
set -e
echo "verify exit=$VE"
test "$VE" -eq 0
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d["accepted"] is True' "$WORK/verify.out"

echo "== local-IS-5 conformance via producer binary =="
"$PROD_LIA" conform --suite "$ROOT/conformance"

echo "== local-IS-5 claims-lint =="
"$VERIFY_LIA" claims-lint --root "$ROOT/docs"
"$VERIFY_LIA" claims-lint --root "$ROOT/README.md"

echo "local-IS-5 OK producer=$PROD_LIA verifier=$VERIFY_LIA bundle=$BUNDLE assurance=AUDIT"
