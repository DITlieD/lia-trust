#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

cargo build -p lia-cli --release
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
LIA="$TARGET_DIR/release/lia"

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/lia-l4-XXXXXX")"
trap 'rm -rf "$WORKDIR"' EXIT
DB="$WORKDIR/journal.sqlite"

SECRET="$(python3 -c 'print("11"*32)')"
EVENT="$(python3 - <<'PY'
import json
from datetime import datetime, timezone
print(json.dumps({
  "family": "raw_harness",
  "harness": "l0b-layer4",
  "raw": {"smoke": "receipt-in-journal"},
  "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
}))
PY
)"

set +e
"$LIA" journal-append --db "$DB" --event "$EVENT" --secret-key-hex "$SECRET" \
  > "$WORKDIR/append.out" 2> "$WORKDIR/append.err"
APPEND_EC=$?
set -e
echo "lia journal-append exit=$APPEND_EC"
cat "$WORKDIR/append.out"
cat "$WORKDIR/append.err" || true
if [[ "$APPEND_EC" -ne 0 ]]; then
  echo "L4 FAIL: append" >&2
  exit 1
fi
if ! grep -q 'signature_hex' "$WORKDIR/append.out"; then
  echo "L4 FAIL: no signature_hex" >&2
  exit 1
fi

set +e
"$LIA" journal-verify "$DB" > "$WORKDIR/verify.out" 2> "$WORKDIR/verify.err"
VERIFY_EC=$?
set -e
echo "lia journal-verify clean exit=$VERIFY_EC"
if [[ "$VERIFY_EC" -ne 0 ]]; then
  cat "$WORKDIR/verify.err" || true
  echo "L4 FAIL: verify clean" >&2
  exit 1
fi

python3 - <<PY
import sqlite3
con = sqlite3.connect("$DB")
con.execute("DROP TRIGGER IF EXISTS journal_rows_no_update")
con.execute("DROP TRIGGER IF EXISTS journal_rows_no_delete")
row = con.execute("SELECT row_hash FROM journal_rows ORDER BY seq LIMIT 1").fetchone()
assert row, "missing row"
h = bytearray(row[0].encode())
h[0] = 48 if h[0] != 48 else 49
con.execute("UPDATE journal_rows SET row_hash = ? WHERE seq = 1", (h.decode(),))
con.commit()
con.close()
PY

set +e
"$LIA" journal-verify "$DB" > "$WORKDIR/verify_bad.out" 2> "$WORKDIR/verify_bad.err"
BAD_EC=$?
set -e
echo "lia journal-verify tampered exit=$BAD_EC"
cat "$WORKDIR/verify_bad.err" || true
if [[ "$BAD_EC" -eq 0 ]]; then
  echo "L4 FAIL: tampered verify exited 0" >&2
  exit 1
fi

echo "L4 OK append=$APPEND_EC verify_clean=$VERIFY_EC verify_tampered=$BAD_EC"
