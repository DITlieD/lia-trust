#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

cargo build -p lia-cli --release
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
LIA="$TARGET_DIR/release/lia"
SECRET="$(python3 -c 'print("33"*32)')"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/lia-is1-XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

REPO="$WORK/repo"
mkdir -p "$REPO/src" "$REPO/.lia"
echo "fn main() {}" >"$REPO/src/main.rs"

CONFIG="$WORK/config.json"
python3 - <<PY
import json
cfg = {
  "allowed_roots": ["$REPO"],
  "home_dir": "/home/agent",
  "cwd": "$REPO",
  "protected_paths": ["$REPO/.lia"],
  "registry": {"serde": ["1.0.0"]},
  "env": {"HOME": "/home/agent"},
}
open("$CONFIG","w").write(json.dumps(cfg, indent=2))
PY

DB="$WORK/journal.db"
RUN_ID="$(python3 -c 'import uuid; print(uuid.uuid4())')"

echo "== IS-1 step1: in-scope write (ALLOW) =="
python3 - <<PY
import json, uuid
open("$WORK/step1.json","w").write(json.dumps({
  "kind": "write_file",
  "action_id": str(uuid.uuid4()),
  "payload": {"path": "src/hello.rs", "is_write": True},
}))
PY
set +e
"$LIA" gate --action "$WORK/step1.json" --config "$CONFIG" \
  --journal "$DB" --secret-key-hex "$SECRET" --key-id is1 --run-id "$RUN_ID" \
  >"$WORK/step1.out" 2>"$WORK/step1.err"
S1=$?
set -e
echo "step1 exit=$S1"
test "$S1" -eq 0
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d["outcomes"][0]["verdict"]=="allow"' "$WORK/step1.out"

echo "== IS-1 step2: fabricated test pass (REFUTED) =="
python3 - <<PY
import json, uuid
open("$WORK/step2.json","w").write(json.dumps({
  "kind": "run_test",
  "action_id": str(uuid.uuid4()),
  "payload": {"claimed_pass": True},
}))
PY
set +e
"$LIA" gate --action "$WORK/step2.json" --config "$CONFIG" \
  --journal "$DB" --secret-key-hex "$SECRET" --key-id is1 --run-id "$RUN_ID" \
  >"$WORK/step2.out" 2>"$WORK/step2.err"
S2=$?
set -e
echo "step2 exit=$S2"
test "$S2" -eq 3
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); o=d["outcomes"][0]; assert o["verdict"]=="refuted"; assert o["reason_code"]=="TEST_FABRICATED_PASS"' "$WORK/step2.out"

echo "== IS-1 step3: out-of-scope delete (DENIED) =="
python3 - <<PY
import json, uuid
open("$WORK/step3.json","w").write(json.dumps({
  "kind": "delete_file",
  "action_id": str(uuid.uuid4()),
  "payload": {"path": "/tmp/outside-lia-is1-delete", "is_delete": True},
}))
PY
set +e
"$LIA" gate --action "$WORK/step3.json" --config "$CONFIG" \
  --journal "$DB" --secret-key-hex "$SECRET" --key-id is1 --run-id "$RUN_ID" \
  >"$WORK/step3.out" 2>"$WORK/step3.err"
S3=$?
set -e
echo "step3 exit=$S3"
test "$S3" -eq 2
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); o=d["outcomes"][0]; assert o["verdict"]=="deny"; assert o["reason_code"]=="FS_OUT_OF_SCOPE"' "$WORK/step3.out"

echo "== IS-1 offline verify =="
"$LIA" journal-verify "$DB"
"$LIA" fixture-bundle \
  --journal "$DB" \
  --outcome "$WORK/step2.out" \
  --secret-key-hex "$SECRET" \
  --key-id is1 \
  --bundle "$WORK/bundle" >"$WORK/bundle.out"
set +e
"$LIA" verify "$WORK/bundle" >"$WORK/verify.out" 2>"$WORK/verify.err"
VE=$?
set -e
echo "lia verify exit=$VE"
test "$VE" -eq 0

echo "IS-1 OK step1=$S1(ALLOW) step2=$S2(REFUTED) step3=$S3(DENIED) verify=$VE"
