#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
HARBOR="$ROOT/bench/harbor"
H="$HARBOR/.venv/bin/harbor"
DS="$HARBOR/datasets/terminal-bench-2"
PIN="$DS/SUBSET24.json"
OUT_OFF="$HARBOR/runs/tb2-off"
OUT_ON="$HARBOR/runs/tb2-on"
MODEL="${LIA_BENCH_MODEL:-swe-1-6}"
BRIDGE="${LIA_BENCH_BASE_URL:-http://127.0.0.1:8810}"
export ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:-devin-local}"
export ANTHROPIC_BASE_URL="$BRIDGE"
export NO_PROXY='*'
export no_proxy='*'

mapfile -t TASKS < <(python3 - <<'PY'
import json
from pathlib import Path
pin=json.loads(Path("'"$PIN"'").read_text())
for t in pin["subset_task_names"]:
    print(t)
PY
)

INCLUDES=()
for t in "${TASKS[@]}"; do
  INCLUDES+=(-i "$t")
done

echo "tb2 OFF n=${#TASKS[@]} model=$MODEL"
"$H" run \
  -p "$DS" \
  -a terminus-2 \
  -m "anthropic/${MODEL}" \
  --ak "api_base=${BRIDGE}" \
  --ae "ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}" \
  --ae "ANTHROPIC_BASE_URL=${BRIDGE}" \
  -n 1 \
  --n-concurrent-agents 1 \
  -o "$OUT_OFF" \
  -y \
  "${INCLUDES[@]}"

echo "tb2 ON (terminus-2 + lia shell gate agent)"
"$H" run \
  -p "$DS" \
  --agent-import-path "bench.harbor.agents.terminus_lia:TerminusLia" \
  -m "anthropic/${MODEL}" \
  --ak "api_base=${BRIDGE}" \
  --ae "ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}" \
  --ae "ANTHROPIC_BASE_URL=${BRIDGE}" \
  -n 1 \
  --n-concurrent-agents 1 \
  -o "$OUT_ON" \
  -y \
  "${INCLUDES[@]}"
