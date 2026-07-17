#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

cargo build -p lia-cli --release
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
LIA="$TARGET_DIR/release/lia"
SECRET="$(python3 -c 'print("22"*32)')"
FIXTURE_ROOT="${1:-$ROOT/bench/gate_fixtures}"

fail=0
ran=0

while IFS= read -r -d '' expected; do
  dir="$(dirname "$expected")"
  ran=$((ran + 1))
  name="${dir#$FIXTURE_ROOT/}"
  echo "== fixture $name =="

  exp_verdict="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["verdict"])' "$expected")"
  exp_reason="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["reason_code"])' "$expected")"
  exp_exit="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["exit_code"])' "$expected")"

  WORK="$(mktemp -d "${TMPDIR:-/tmp}/lia-gf-XXXXXX")"
  DB="$WORK/journal.db"
  OUT="$WORK/out.json"
  BUNDLE="$WORK/bundle"

  set +e
  "$LIA" gate \
    --request "$dir/request.json" \
    --config "$dir/config.json" \
    --journal "$DB" \
    --secret-key-hex "$SECRET" \
    --key-id "fixture" \
    >"$OUT" 2>"$WORK/err"
  EC=$?
  set -e

  got_verdict="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["outcomes"][0]["verdict"])' "$OUT")"
  got_reason="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["outcomes"][0]["reason_code"])' "$OUT")"

  ok=1
  if [[ "$got_verdict" != "$exp_verdict" ]]; then
    echo "FAIL verdict: got=$got_verdict expected=$exp_verdict" >&2
    ok=0
  fi
  if [[ "$got_reason" != "$exp_reason" ]]; then
    echo "FAIL reason: got=$got_reason expected=$exp_reason" >&2
    ok=0
  fi
  if [[ "$EC" -ne "$exp_exit" ]]; then
    echo "FAIL exit: got=$EC expected=$exp_exit" >&2
    ok=0
  fi
  if ! grep -q 'signature_hex' "$OUT"; then
    echo "FAIL missing journal signature_hex" >&2
    ok=0
  fi

  set +e
  "$LIA" journal-verify "$DB" >"$WORK/jv.out" 2>"$WORK/jv.err"
  JV=$?
  set -e
  if [[ "$JV" -ne 0 ]]; then
    echo "FAIL journal-verify exit=$JV" >&2
    cat "$WORK/jv.err" >&2 || true
    ok=0
  fi

  set +e
  "$LIA" fixture-bundle \
    --journal "$DB" \
    --outcome "$OUT" \
    --secret-key-hex "$SECRET" \
    --key-id fixture \
    --bundle "$BUNDLE" \
    >"$WORK/bundle.out" 2>"$WORK/bundle.err"
  BB=$?
  set -e
  if [[ "$BB" -ne 0 ]]; then
    echo "FAIL fixture-bundle exit=$BB" >&2
    cat "$WORK/bundle.err" >&2 || true
    ok=0
  fi

  set +e
  "$LIA" verify "$BUNDLE" >"$WORK/verify.out" 2>"$WORK/verify.err"
  VE=$?
  set -e
  if [[ "$VE" -ne 0 ]]; then
    echo "FAIL lia verify exit=$VE" >&2
    cat "$WORK/verify.err" >&2 || true
    cat "$WORK/verify.out" >&2 || true
    ok=0
  fi

  if [[ "$ok" -eq 1 ]]; then
    echo "OK $name verdict=$got_verdict reason=$got_reason exit=$EC verify=$VE"
  else
    fail=$((fail + 1))
    echo "---- out ----" >&2
    cat "$OUT" >&2 || true
    echo "---- err ----" >&2
    cat "$WORK/err" >&2 || true
  fi
  rm -rf "$WORK"
done < <(find "$FIXTURE_ROOT" -name expected.json -print0 | sort -z)

echo "fixtures ran=$ran fail=$fail"
if [[ "$fail" -ne 0 || "$ran" -eq 0 ]]; then
  exit 1
fi
exit 0
