#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
H="$ROOT/bench/harbor/.venv/bin/harbor"
export ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:-devin-local}"
export ANTHROPIC_BASE_URL="${LIA_BENCH_BASE_URL:-http://127.0.0.1:8810}"
export LIA_BIN="${LIA_BIN:-$ROOT/target/release/lia}"
export NO_PROXY='*'
export no_proxy='*'
export PYTHONPATH="$ROOT/bench/harbor:${PYTHONPATH:-}"
MODEL="${LIA_BENCH_MODEL:-swe-1-6}"
BRIDGE="${LIA_BENCH_BASE_URL:-http://127.0.0.1:8810}"

summarize_job() {
  local jobdir="$1"
  local out="$2"
  python3 - "$jobdir" "$out" <<'PY'
import json, sys
from pathlib import Path
job = Path(sys.argv[1])
out = Path(sys.argv[2])
res = json.loads((job / "result.json").read_text())
stats = res.get("stats") or {}
evals = stats.get("evals") or {}
mean = None
for ev in evals.values():
    for m in ev.get("metrics") or []:
        if "mean" in m:
            mean = m["mean"]
out.write_text(
    json.dumps(
        {
            "job": str(job),
            "finished_at": res.get("finished_at"),
            "n_total": res.get("n_total_trials"),
            "stats": stats,
            "mean_reward": mean,
            "n_input_tokens": stats.get("n_input_tokens"),
            "n_output_tokens": stats.get("n_output_tokens"),
        },
        indent=2,
    )
    + "\n"
)
print("wrote", out, "mean", mean)
PY
}

OFF_JOB=$(ls -dt bench/harbor/runs/tb2-off/*/ 2>/dev/null | head -1)
echo "OFF job=$OFF_JOB"
summarize_job "$OFF_JOB" bench/harbor/results/tb2-off.json

DS=bench/harbor/datasets/terminal-bench-2
mapfile -t TASKS < <(python3 -c "import json; print('\n'.join(json.load(open('$DS/SUBSET24.json'))['subset_task_names']))")
INCLUDES=()
for t in "${TASKS[@]}"; do
  INCLUDES+=(-i "$t")
done

echo "TB2 ON terminus-lia"
"$H" run \
  -p "$DS" \
  --agent-import-path "agents.terminus_lia:TerminusLia" \
  -m "anthropic/${MODEL}" \
  --ak "api_base=${BRIDGE}" \
  --ae "ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}" \
  --ae "ANTHROPIC_BASE_URL=${BRIDGE}" \
  -n 1 \
  --n-concurrent-agents 1 \
  -o bench/harbor/runs/tb2-on \
  -y \
  "${INCLUDES[@]}"

ON_JOB=$(ls -dt bench/harbor/runs/tb2-on/*/ 2>/dev/null | head -1)
summarize_job "$ON_JOB" bench/harbor/results/tb2-on.json

echo "Claw Lite: all 80 OFF then ON"
CLAW=bench/harbor/datasets/claw-swe-lite-harbor
mapfile -t ALL80 < <(python3 -c "
from pathlib import Path
print('\n'.join(sorted(p.name for p in Path('$CLAW').iterdir() if p.is_dir() and (p/'task.toml').exists())))
")
CINC=()
for t in "${ALL80[@]}"; do
  CINC+=(-i "$t")
done

"$H" run \
  -p "$CLAW" \
  -a terminus-2 \
  -m "anthropic/${MODEL}" \
  --ak "api_base=${BRIDGE}" \
  --ae "ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}" \
  --ae "ANTHROPIC_BASE_URL=${BRIDGE}" \
  -n 1 \
  --n-concurrent-agents 1 \
  -o bench/harbor/runs/claw-off \
  -y \
  "${CINC[@]}"

CLAW_OFF=$(ls -dt bench/harbor/runs/claw-off/*/ 2>/dev/null | head -1)
summarize_job "$CLAW_OFF" bench/harbor/results/claw-off.json

"$H" run \
  -p "$CLAW" \
  --agent-import-path "agents.terminus_lia:TerminusLia" \
  -m "anthropic/${MODEL}" \
  --ak "api_base=${BRIDGE}" \
  --ae "ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}" \
  --ae "ANTHROPIC_BASE_URL=${BRIDGE}" \
  -n 1 \
  --n-concurrent-agents 1 \
  -o bench/harbor/runs/claw-on \
  -y \
  "${CINC[@]}"

CLAW_ON=$(ls -dt bench/harbor/runs/claw-on/*/ 2>/dev/null | head -1)
summarize_job "$CLAW_ON" bench/harbor/results/claw-on.json

python3 bench/harbor/scripts/publish_scorecard.py
echo "utility lanes done"
