#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

PIN="$(tr -d '[:space:]' < "$ROOT/tools/cargo-llvm-cov.pin")"
export CARGO_LLVM_COV_VERSION="${CARGO_LLVM_COV_VERSION:-$PIN}"

FIXTURE="$ROOT/tools/scripts/fixtures/llvm-cov-settling.json"
if [[ "${L0B_SETTLING_FIXTURE_ONLY:-}" == "1" ]]; then
  python3 "$ROOT/tools/scripts/layer3_cov_gate.py" \
    --json "$FIXTURE" \
    --settling \
    --require-zero l0b_settling_unwired_stub \
    --require-hit append_signed \
    --require-hit verify_chain \
    --require-hit parse_event
  echo "SETTLING OK (fixture)"
  exit 0
fi

if ! cargo llvm-cov --version >/dev/null 2>&1; then
  cargo install cargo-llvm-cov --version "${CARGO_LLVM_COV_VERSION}" --locked
fi

VER_LINE="$(cargo llvm-cov --version | head -n1)"
echo "cargo-llvm-cov: $VER_LINE"
echo "$VER_LINE" | grep -q "${CARGO_LLVM_COV_VERSION}"

STUB_FILE="$ROOT/crates/lia-cli/src/l0b_settling_stub.rs"
MAIN_RS="$ROOT/crates/lia-cli/src/main.rs"
MOD_LINE="mod l0b_settling_stub;"

cleanup() {
  rm -f "$STUB_FILE"
  if [[ -f "$MAIN_RS" ]] && grep -qxF "$MOD_LINE" "$MAIN_RS"; then
    tmp="$(mktemp)"
    grep -vxF "$MOD_LINE" "$MAIN_RS" > "$tmp"
    mv "$tmp" "$MAIN_RS"
  fi
}
trap cleanup EXIT

cat > "$STUB_FILE" <<'EOF'
#[allow(dead_code)]
pub fn l0b_settling_unwired_stub() {
    let _ = 1u8;
}
EOF

if ! grep -qxF "$MOD_LINE" "$MAIN_RS"; then
  printf '\n%s\n' "$MOD_LINE" >> "$MAIN_RS"
fi

mkdir -p "$ROOT/coverage"
OUT_JSON="$ROOT/coverage/llvm-cov-settling.json"

cargo llvm-cov -p lia-cli -p lia-journal -p lia-protocol \
  --json --output-path "$OUT_JSON" \
  --ignore-filename-regex '(tests?/|/target/)' \
  -- --test-threads=1

test -f "$OUT_JSON"

python3 "$ROOT/tools/scripts/layer3_cov_gate.py" \
  --json "$OUT_JSON" \
  --settling \
  --require-zero l0b_settling_unwired_stub \
  --require-hit append_signed \
  --require-hit verify_chain \
  --require-hit parse_event

echo "SETTLING OK"
