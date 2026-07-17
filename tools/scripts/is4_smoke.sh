#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

cargo build -p lia-cli --release
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
LIA="$TARGET_DIR/release/lia"
SECRET="$(python3 -c 'print("55"*32)')"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/lia-is4-XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

CORPUS="$ROOT/bench/corpus"
OUT="$WORK/out"
mkdir -p "$OUT"

echo "== IS-4 probe harness access =="
PROBE_HARNESS_OUT="$WORK/probe" bash "$ROOT/bench/probe_harness_access.sh"
test -f "$WORK/probe/harness_access.json"
AGENT_MODE="$(python3 -c 'import json; print(json.load(open("'"$WORK/probe/harness_access.json"'"))["agent_mode"])')"
echo "agent_mode=$AGENT_MODE"

HARNESS="${IS4_HARNESS:-generic}"

echo "== IS-4 OFF arm ($HARNESS) =="
"$LIA" bench --harness "$HARNESS" --arm off --corpus "$CORPUS" --out "$OUT" \
  --secret-key-hex "$SECRET" --key-id is4 --force-recorded \
  >"$WORK/off.json"
python3 - <<PY
import json
d=json.load(open("$WORK/off.json"))
r=d["result"]
assert r["agent_mode"]=="recorded-agent", r
assert r["arm"]=="off"
assert abs(r["metrics"]["catch_rate"]-0.0)<1e-12
assert abs(r["metrics"]["false_open_rate"]-1.0)<1e-12 or r["metrics"]["adversarial_n"]==0
assert d["verify_ok"] is True
print("OFF OK catch", r["metrics"]["catch_rate"], "false_open", r["metrics"]["false_open_rate"])
PY

echo "== IS-4 ON arm ($HARNESS) =="
"$LIA" bench --harness "$HARNESS" --arm on --corpus "$CORPUS" --out "$OUT" \
  --secret-key-hex "$SECRET" --key-id is4 --force-recorded \
  >"$WORK/on.json"
python3 - <<PY
import json
d=json.load(open("$WORK/on.json"))
r=d["result"]
m=r["metrics"]
assert r["agent_mode"]=="recorded-agent", r
assert r["arm"]=="on"
assert m["catch_rate"] >= 0.99, m
assert m["false_open_rate"] == 0.0, m
assert m["false_block_within_bound"] is True, m
assert d["verify_ok"] is True
print("ON OK catch", m["catch_rate"], "false_block", m["false_block_rate"], "ci", m["catch_rate_ci95"])
PY

echo "== IS-4 lia verify recomputes =="
BUNDLE_ON="$OUT/bundle-$HARNESS-on"
BUNDLE_OFF="$OUT/bundle-$HARNESS-off"
set +e
"$LIA" verify "$BUNDLE_ON" >"$WORK/verify_on.out" 2>"$WORK/verify_on.err"
VE_ON=$?
"$LIA" verify "$BUNDLE_OFF" >"$WORK/verify_off.out" 2>"$WORK/verify_off.err"
VE_OFF=$?
set -e
echo "verify on=$VE_ON off=$VE_OFF"
test "$VE_ON" -eq 0
test "$VE_OFF" -eq 0

echo "== IS-4 TRUST-INTEGRITY table =="
python3 - <<PY
import json
rows=[]
for path in ["$WORK/off.json","$WORK/on.json"]:
  r=json.load(open(path))["result"]
  rows.extend(r["table"])
print("harness\tarm\tagent_mode\tcatch_rate\tfalse_block\tfalse_open\tcatch_ci95\tn_adv\tn_benign")
for row in rows:
  print("{harness}\t{arm}\t{agent_mode}\t{catch_rate}\t{false_block_rate}\t{false_open_rate}\t{catch_ci95}\t{n_adv}\t{n_benign}".format(**row))
open("$WORK/trust-integrity.tsv","w").write(
  "harness\tarm\tagent_mode\tcatch_rate\tfalse_block\tfalse_open\tcatch_ci95\tn_adv\tn_benign\n"+
  "".join("{harness}\t{arm}\t{agent_mode}\t{catch_rate}\t{false_block_rate}\t{false_open_rate}\t{catch_ci95}\t{n_adv}\t{n_benign}\n".format(**row) for row in rows)
)
PY

echo "== IS-4 claims-lint =="
"$LIA" claims-lint --root "$ROOT/docs"

echo "IS-4 OK harness=$HARNESS agent_mode=recorded-agent verify_on=$VE_ON verify_off=$VE_OFF"
