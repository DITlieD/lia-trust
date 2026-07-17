#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

cargo build -p lia-cli --release
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
LIA="$TARGET_DIR/release/lia"
SECRET="$(python3 -c 'print("44"*32)')"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/lia-l4g-XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

python3 - <<PY
import json, uuid
cfg = {
  "allowed_roots": ["/work/repo"],
  "home_dir": "/home/agent",
  "cwd": "/work/repo",
  "protected_paths": ["/work/repo/.lia"],
  "registry": {},
  "env": {"HOME": "/home/agent"},
}
open("$WORK/config.json","w").write(json.dumps(cfg))
open("$WORK/request.json","w").write(json.dumps({
  "gate_id": "test-integrity",
  "action_id": str(uuid.uuid4()),
  "kind": "run_test",
  "payload": {"claimed_pass": True},
}))
PY

set +e
"$LIA" gate --request "$WORK/request.json" --config "$WORK/config.json" \
  --journal "$WORK/journal.db" --secret-key-hex "$SECRET" --key-id l4gate \
  >"$WORK/out.json" 2>"$WORK/err"
EC=$?
set -e
echo "lia gate exit=$EC"
test "$EC" -eq 3
grep -q 'signature_hex' "$WORK/out.json"
grep -q 'TEST_FABRICATED_PASS' "$WORK/out.json"

"$LIA" journal-verify "$WORK/journal.db"
"$LIA" fixture-bundle \
  --journal "$WORK/journal.db" \
  --outcome "$WORK/out.json" \
  --secret-key-hex "$SECRET" \
  --key-id l4gate \
  --bundle "$WORK/bundle"
"$LIA" verify "$WORK/bundle"

echo "L4 gate-receipt OK"
