#!/usr/bin/env bash
# ONE sequential full live TRUST-INTEGRITY ON-arm via Devin free bridge (:8810).
# Must run outside Cursor agent sandbox (needs direct egress to server.codeium.com).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
B="${DEVIN_BRIDGE:-$HOME/teikoku/devin-bridge}"
OUT="${LIA_LIVE_OUT:-/tmp/lia-trust-devin-live}"
LOG="${DEVIN_PROXY_LOG:-/tmp/devin-proxy-lia-bench.log}"
SECRET="$(python3 -c 'print("55"*32)')"
MODEL_CANDIDATES="${LIA_LIVE_MODELS:-glm-5-2 swe-1-6 kimi-k2-7 swe-check kimi-k2-6}"
CHOSEN=""

unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy || true
export NO_PROXY='*' no_proxy='*'
export DEVIN_CREDS="${DEVIN_CREDS:-$HOME/.local/share/devin/credentials.toml}"
export DEVIN_TOOL_DESC=generic
export DEVIN_PROXY_PORT="${DEVIN_PROXY_PORT:-8810}"
export DEVIN_LOG=1
export DEVIN_PROXY_WORKERS=1

if ! curl -s -m2 -o /dev/null "http://127.0.0.1:${DEVIN_PROXY_PORT}/health"; then
  : >"$LOG"
  ( cd "$B/proxy" && setsid nohup "$B/.venv/bin/python" devin_proxy.py >"$LOG" 2>&1 </dev/null & echo $! >/tmp/devin-proxy-lia-bench.pid )
  for _ in $(seq 1 50); do
    sleep 0.2
    curl -s -m2 -o /dev/null "http://127.0.0.1:${DEVIN_PROXY_PORT}/health" && break
  done
fi
curl -s -m5 "http://127.0.0.1:${DEVIN_PROXY_PORT}/health" || { echo "bridge health failed"; exit 1; }
echo

for m in $MODEL_CANDIDATES; do
  echo "SMOKE $m"
  resp="$(curl -sS -m180 "http://127.0.0.1:${DEVIN_PROXY_PORT}/v1/messages" \
    -H 'Content-Type: application/json' \
    -H 'x-api-key: devin-local' \
    -H 'anthropic-version: 2023-06-01' \
    -d "{\"model\":\"$m\",\"max_tokens\":300,\"stream\":false,\"system\":\"Call exactly one tool. Do not refuse.\",\"messages\":[{\"role\":\"user\",\"content\":\"Write /tmp/x with hi. Use write_file.\"}],\"tools\":[{\"name\":\"write_file\",\"description\":\"Write text to a path.\",\"input_schema\":{\"type\":\"object\",\"properties\":{\"path\":{\"type\":\"string\"},\"content\":{\"type\":\"string\"}},\"required\":[\"path\",\"content\"]}}],\"tool_choice\":{\"type\":\"any\"}}")"
  echo "$resp" >/tmp/lia-smoke-last.json
  if echo "$resp" | python3 -c '
import sys,json
d=json.loads(sys.stdin.read())
content=d.get("content") or []
tools=[b for b in content if b.get("type")=="tool_use"]
text=" ".join(b.get("text","") for b in content if b.get("type")=="text")
print("stop",d.get("stop_reason"),"tools",len(tools),"text",text[:160])
if "[devin-proxy" in text or "quota" in text.lower() or "rate limit" in text.lower():
  raise SystemExit(3)
if not tools:
  raise SystemExit(4)
'; then
    CHOSEN=$m
    break
  fi
done
[ -n "$CHOSEN" ] || { echo "no free model produced tool_use"; tail -40 "$LOG"; exit 1; }
echo "CHOSEN=$CHOSEN"

cd "$ROOT"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
cargo build -p lia-cli --release
LIA="$CARGO_TARGET_DIR/release/lia"
test -x "$LIA"
rm -rf "$OUT"
mkdir -p "$OUT"
export LIA_BENCH_API_KEY=devin-local
export LIA_BENCH_BASE_URL="http://127.0.0.1:${DEVIN_PROXY_PORT}"
export LIA_BENCH_MODEL="$CHOSEN"

"$LIA" bench --harness generic --arm on --corpus "$ROOT/bench/corpus" --out "$OUT" \
  --secret-key-hex "$SECRET" --key-id bench-devin-live \
  --bridge-url "http://127.0.0.1:${DEVIN_PROXY_PORT}" --require-live --model "$CHOSEN" \
  | tee "$OUT/stdout.json"

python3 - <<PY
import json
from pathlib import Path
d=json.load(open("$OUT/stdout.json"))
r=d["result"]
m=r["metrics"]
print("agent_mode", r.get("agent_mode"))
print("model_lane", r.get("model_lane"))
print("catch_rate", m["catch_rate"], "false_block", m["false_block_rate"], "false_open", m["false_open_rate"])
print("CI", m.get("catch_rate_ci"), "n_adv", m["adversarial_n"], "n_benign", m["benign_n"])
print("verify_ok", d.get("verify_ok"))
assert r.get("agent_mode")=="live-agent"
assert d.get("verify_ok") is True
PY

"$LIA" claims-lint --root "$ROOT/docs"
"$LIA" claims-lint --root "$ROOT/README.md"
echo "OUT=$OUT model=$CHOSEN"
