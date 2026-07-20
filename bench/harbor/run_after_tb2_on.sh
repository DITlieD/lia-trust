#!/usr/bin/env bash
# Wait for live TB2 ON (pid) + Claw image pulls, then run Claw 80 OFF→ON and scorecard.
# Does NOT start a second TB2 ON.
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
TB2_PID="${TB2_ON_PID:-335529}"
PULL_PID="${CLAW_PULL_PID:-335530}"
LOG=/tmp/harbor-after-tb2-on.log
exec > >(tee -a "$LOG") 2>&1

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
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(
    json.dumps(
        {
            "job": str(job),
            "status": "MEASURED" if res.get("finished_at") else "PARTIAL",
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

echo "=== wait TB2 ON pid=$TB2_PID ==="
while kill -0 "$TB2_PID" 2>/dev/null; do
  ON_JOB=$(ls -dt bench/harbor/runs/tb2-on/*/ 2>/dev/null | head -1 || true)
  if [[ -n "${ON_JOB:-}" && -f "$ON_JOB/result.json" ]]; then
    python3 -c "import json;d=json.load(open('$ON_JOB/result.json'));s=d['stats'];print('tb2-on',s.get('n_completed_trials'),'done',s.get('n_running_trials'),'run',s.get('n_pending_trials'),'pend',s.get('n_errored_trials'),'err','fin',d.get('finished_at'))"
  fi
  sleep 120
done
echo "TB2 ON process exited"

ON_JOB=$(ls -dt bench/harbor/runs/tb2-on/*/ 2>/dev/null | head -1)
# wait for finished_at in case harbor flushes after pid exit
for _ in $(seq 1 30); do
  fin=$(python3 -c "import json;print(json.load(open('$ON_JOB/result.json')).get('finished_at') or '')")
  [[ -n "$fin" ]] && break
  sleep 10
done
summarize_job "$ON_JOB" bench/harbor/results/tb2-on.json
python3 bench/harbor/scripts/publish_scorecard.py || true

echo "=== wait Claw image pulls pid=$PULL_PID ==="
while kill -0 "$PULL_PID" 2>/dev/null; do
  have=$(rg -c '^HAVE |^Status: Downloaded|^CLAW_PULLS' /tmp/claw-image-pulls.log 2>/dev/null || echo 0)
  echo "pulls still running; log markers≈$have"
  sleep 120
done
if ! rg -q 'CLAW_PULLS_DONE' /tmp/claw-image-pulls.log 2>/dev/null; then
  echo "WARN: pull pid gone without CLAW_PULLS_DONE; recounting local images"
  have=0; miss=0
  while read -r img; do
    [[ -z "$img" ]] && continue
    if docker image inspect "$img" >/dev/null 2>&1; then have=$((have+1)); else miss=$((miss+1)); echo "MISSING $img"; fi
  done < /tmp/claw-images.txt
  echo "local_have=$have miss=$miss"
  if [[ "$miss" -gt 0 ]]; then
    echo "resuming missing pulls"
    while read -r img; do
      [[ -z "$img" ]] && continue
      if docker image inspect "$img" >/dev/null 2>&1; then
        echo "HAVE $img"
      else
        echo "PULL $img"
        docker pull --platform linux/amd64 "$img" || echo "FAIL $img"
      fi
    done < /tmp/claw-images.txt
    echo CLAW_PULLS_DONE
  fi
fi
echo "Claw images ready"

echo "=== Claw Lite 80 OFF ==="
CLAW=bench/harbor/datasets/claw-swe-lite-harbor
mapfile -t ALL80 < <(python3 -c "
from pathlib import Path
print('\n'.join(sorted(p.name for p in Path('$CLAW').iterdir() if p.is_dir() and (p/'task.toml').exists())))
")
CINC=()
for t in "${ALL80[@]}"; do
  CINC+=(-i "$t")
done
echo "n_tasks=${#ALL80[@]}"

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
python3 bench/harbor/scripts/publish_scorecard.py || true

echo "=== Claw Lite 80 ON (terminus-lia) ==="
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
echo "=== ALL UTILITY LANES DONE ==="
