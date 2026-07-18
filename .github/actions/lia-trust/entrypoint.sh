#!/usr/bin/env bash
set -euo pipefail

ACTION_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$ACTION_DIR/../../.." && pwd)"

REPO="${LIA_REPO:-.}"
BASE="${LIA_BASE:-HEAD~1}"
HEAD="${LIA_HEAD:-HEAD}"
EVIDENCE="${LIA_EVIDENCE:-.}"
OUT="${LIA_OUT:-lia-bundle}"
SECRET="${LIA_SECRET_KEY_HEX:?LIA_SECRET_KEY_HEX required}"
export OUT

if [[ -n "${LIA_BIN:-}" && -x "$LIA_BIN" ]]; then
  LIA="$LIA_BIN"
else
  cargo build -p lia-cli --release --manifest-path "$ROOT/Cargo.toml"
  TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
  LIA="$TARGET_DIR/release/lia"
fi

mkdir -p "$OUT"
"$LIA" verify-run \
  --base "$BASE" \
  --head "$HEAD" \
  --evidence "$EVIDENCE" \
  --repo "$REPO" \
  --out "$OUT" \
  --secret-key-hex "$SECRET" \
  --key-id action \
  >"${OUT}/verify-run.json"

python3 - <<PY
import json, os
out = os.environ["OUT"]
d = json.load(open(out + "/verify-run.json"))
assert d.get("assurance_level") == "AUDIT", d
assert d.get("prevention") is False, d
assert d.get("accepted") is True, d
print("bundle=" + d["bundle"])
gh = os.environ.get("GITHUB_OUTPUT")
if gh:
    open(gh, "a").write(f'bundle={d["bundle"]}\n')
PY

echo "LIA action AUDIT bundle ready at $OUT"
