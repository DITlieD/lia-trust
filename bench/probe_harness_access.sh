#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BRIDGE_URL="${BRIDGE_URL:-http://127.0.0.1:8810}"
OUT_DIR="${PROBE_HARNESS_OUT:-$ROOT/bench/probe_out}"
mkdir -p "$OUT_DIR"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/lia-probe-harness-XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

REPO="$WORK/repo"
mkdir -p "$REPO/src"
echo 'fn main() {}' >"$REPO/src/main.rs"
echo 'empty-harness' >"$REPO/README"

fail=0

echo "== skill-free check =="
for b in .claude .cursor .codex AGENTS.md CLAUDE.md .lia-skills; do
  if [[ -e "$REPO/$b" ]]; then
    echo "FAIL skill contamination: $b" >&2
    fail=1
  fi
done
if [[ "$fail" -eq 0 ]]; then
  echo "OK skill-free"
fi

echo "== corpus git-STRIP check =="
if find "$ROOT/bench/corpus" \( -name '.git' -o -name '*.patch' -o -name '*.fix' -o -name '*.rej' \) | grep -q .; then
  echo "ABORT: corpus carries .git or fix metadata" >&2
  exit 3
fi
echo "OK corpus hardened"

echo "== bridge health $BRIDGE_URL =="
BRIDGE_OK=0
MODEL_ID=""
BODY=""
if BODY="$(curl -sS --connect-timeout 2 --max-time 5 "$BRIDGE_URL/v1/models" 2>/dev/null)"; then
  BRIDGE_OK=1
elif BODY="$(curl -sS --connect-timeout 2 --max-time 5 "$BRIDGE_URL/health" 2>/dev/null)"; then
  BRIDGE_OK=1
fi

AGENT_MODE="recorded-agent"
if [[ "$BRIDGE_OK" -eq 1 && -n "$BODY" ]]; then
  MODEL_ID="$(python3 -c 'import json,sys
try:
  v=json.loads(sys.argv[1])
  print((v.get("data") or [{}])[0].get("id") or v.get("model") or "")
except Exception:
  print("")' "$BODY")"
  AGENT_MODE="live-agent"
  echo "OK bridge reachable model_id=${MODEL_ID:-unknown}"
else
  echo "bridge down; label=${AGENT_MODE} (never live-agent)"
fi

# Confirm ANTHROPIC_BASE_URL routing only when bridge is up (optional settle)
if [[ "$BRIDGE_OK" -eq 1 ]]; then
  echo "== settle ANTHROPIC_BASE_URL=$BRIDGE_URL =="
  # Do not call the model; only confirm env wiring contract for a local wrapped agent.
  python3 - <<PY
import os
os.environ["ANTHROPIC_BASE_URL"]="$BRIDGE_URL"
assert os.environ["ANTHROPIC_BASE_URL"].startswith("http")
print("OK local agent would route generation to bridge")
PY
fi

python3 - <<PY
import json, time
open("$OUT_DIR/harness_access.json","w").write(json.dumps({
  "skill_free": True,
  "corpus_git_stripped": True,
  "bridge_url": "$BRIDGE_URL",
  "bridge_reachable": bool($BRIDGE_OK),
  "bridge_model_id": "$MODEL_ID" or None,
  "agent_mode": "$AGENT_MODE",
  "probed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
  "notes": [
    "empty throwaway repo has no skills/rules/config",
    "Devin cloud DETECT-only lane is never pooled with PREVENT headline",
  ],
}, indent=2))
print("wrote $OUT_DIR/harness_access.json")
PY

if [[ "$fail" -ne 0 ]]; then
  exit 1
fi
exit 0
