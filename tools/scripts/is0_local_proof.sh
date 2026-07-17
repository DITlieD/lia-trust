#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

PROOF_DIR="$ROOT/coverage/is0-proof"
rm -rf "$PROOF_DIR"
mkdir -p "$PROOF_DIR"

cargo build -p lia_wire_check -p lia_gate_freeze --release
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
WIRE="$TARGET_DIR/release/lia_wire_check"
FREEZE="$TARGET_DIR/release/lia_gate_freeze"

SEED_DIR="$PROOF_DIR/seed_crate/src"
mkdir -p "$SEED_DIR"
cat > "$SEED_DIR/lib.rs" <<'EOF'
pub fn seed_unwired_dark() {}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_test_caller() {
        seed_unwired_dark();
    }
}
EOF

set +e
"$WIRE" --root "$PROOF_DIR/seed_crate" --files src/lib.rs \
  --allowlist /dev/null > "$PROOF_DIR/wire_check.out" 2> "$PROOF_DIR/wire_check.err"
WIRE_EC=$?
set -e
echo "lia_wire_check exit=$WIRE_EC"
cat "$PROOF_DIR/wire_check.out" || true
cat "$PROOF_DIR/wire_check.err" || true

if [[ "$WIRE_EC" -eq 0 ]]; then
  echo "IS-0 FAIL: wire-dark accepted" >&2
  exit 1
fi
if ! grep -q 'seed_unwired_dark' "$PROOF_DIR/wire_check.out" "$PROOF_DIR/wire_check.err"; then
  echo "IS-0 FAIL: dark symbol missing" >&2
  exit 1
fi

cp tools/wire-dark-allowlist.txt "$PROOF_DIR/wire-dark-allowlist.bak"
printf '\n' >> tools/wire-dark-allowlist.txt
set +e
"$FREEZE" --check > "$PROOF_DIR/freeze_check.out" 2> "$PROOF_DIR/freeze_check.err"
FREEZE_EC=$?
set -e
mv "$PROOF_DIR/wire-dark-allowlist.bak" tools/wire-dark-allowlist.txt

echo "lia_gate_freeze --check exit=$FREEZE_EC"
cat "$PROOF_DIR/freeze_check.out" || true
cat "$PROOF_DIR/freeze_check.err" || true

if [[ "$FREEZE_EC" -eq 0 ]]; then
  echo "IS-0 FAIL: freeze edit accepted" >&2
  exit 1
fi
if ! grep -Eqi 'BLOCK|Modified|mismatch' "$PROOF_DIR/freeze_check.out" "$PROOF_DIR/freeze_check.err"; then
  echo "IS-0 FAIL: freeze detail missing" >&2
  exit 1
fi

set +e
"$FREEZE" --check > /dev/null
CLEAN_EC=$?
set -e
if [[ "$CLEAN_EC" -ne 0 ]]; then
  echo "IS-0 FAIL: clean freeze exit=$CLEAN_EC" >&2
  exit 1
fi

{
  echo "IS-0 PASS"
  echo "lia_wire_check seed_unwired_dark exit=$WIRE_EC"
  echo "lia_gate_freeze frozen edit exit=$FREEZE_EC"
  echo "lia_gate_freeze clean exit=$CLEAN_EC"
} | tee "$PROOF_DIR/SUMMARY.txt"
