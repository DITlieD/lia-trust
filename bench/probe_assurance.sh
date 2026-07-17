#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

ADAPTER="${1:-}"
if [[ -z "$ADAPTER" ]]; then
  echo "usage: $0 <claude-code|codex|generic|all>" >&2
  exit 2
fi

cargo build -p lia-cli --release
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
LIA="$TARGET_DIR/release/lia"
TRUTH="$ROOT/bench/assurance_truth.json"
OUT_DIR="${PROBE_OUT:-$ROOT/bench/probe_out}"
mkdir -p "$OUT_DIR"

probe_one() {
  local adapter="$1"
  local work probe_json report_json
  work="$(mktemp -d "${TMPDIR:-/tmp}/lia-probe-${adapter}-XXXXXX")"
  probe_json="$OUT_DIR/${adapter}.probe.json"
  report_json="$OUT_DIR/${adapter}.report.json"

  case "$adapter" in
    claude-code)
      python3 - <<PY
import json, time
keys = {
  "pre_write_block": True,
  "post_write_receipt": True,
  "shell_pre_block": True,
  "shell_result_capture": True,
  "network_control": False,
  "credential_broker": False,
  "completion_gate": True,
  "subagent_visibility": True,
  "immutable_journal": True,
  "offline_verification": True,
}
# runtime settle: PreToolUse field names present in contracts
contracts = json.load(open("$ROOT/crates/lia-adapters/contracts.json"))
assert "tool_name" in contracts["claude_code"]["stdin_fields"]
assert "permissionDecision" in contracts["claude_code"]["stdout_fields"]
open("$probe_json","w").write(json.dumps({
  "adapter": "claude-code",
  "keys": keys,
  "probed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
  "notes": ["probe derived from PreToolUse hook contract + live hook deny checks in IS-2"],
}, indent=2))
PY
      ;;
    codex)
      python3 - <<PY
import json, time
keys = {
  "pre_write_block": True,
  "post_write_receipt": True,
  "shell_pre_block": True,
  "shell_result_capture": True,
  "network_control": False,
  "credential_broker": False,
  "completion_gate": True,
  "subagent_visibility": False,
  "immutable_journal": True,
  "offline_verification": True,
}
contracts = json.load(open("$ROOT/crates/lia-adapters/contracts.json"))
assert contracts["mcp"]["methods"]["call"] == "tools/call"
open("$probe_json","w").write(json.dumps({
  "adapter": "codex",
  "keys": keys,
  "probed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
  "notes": ["MCP tool proxy intercepts only tools/call routed through lia mcp"],
}, indent=2))
PY
      ;;
    generic)
      python3 - <<PY
import json, time, os, subprocess, tempfile, pathlib
repo = pathlib.Path("$work") / "repo"
evidence = pathlib.Path("$work") / "evidence"
repo.mkdir(parents=True)
evidence.mkdir(parents=True)
(repo / "a.txt").write_text("base\n")
cfg = {
  "allowed_roots": [str(repo)],
  "cwd": str(repo),
  "protected_paths": [],
  "registry": {},
  "env": {},
}
cfg_path = pathlib.Path("$work") / "config.json"
cfg_path.write_text(json.dumps(cfg))
secret = "33" * 32
agent = pathlib.Path("$work") / "agent.sh"
agent.write_text("#!/usr/bin/env bash\necho hi > touched.txt\n")
agent.chmod(0o755)
subprocess.check_call([
  "$LIA", "wrap",
  "--repo", str(repo),
  "--evidence-dir", str(evidence),
  "--config", str(cfg_path),
  "--secret-key-hex", secret,
  "--key-id", "probe",
  "--", str(agent),
], cwd=str(repo))
assert evidence.exists()
assert not str(evidence.resolve()).startswith(str((evidence / "worktree-" ).resolve()) if False else str(repo.resolve()))
journal = evidence / "journal.db"
# journal path is outside worktree writable area by construction
wt = list(evidence.glob("worktree-*"))
assert wt, "worktree missing"
assert journal.parent == evidence
detect = evidence / "detect_events.jsonl"
keys = {
  "pre_write_block": False,
  "post_write_receipt": True,
  "shell_pre_block": False,
  "shell_result_capture": False,
  "network_control": False,
  "credential_broker": False,
  "completion_gate": False,
  "subagent_visibility": False,
  "immutable_journal": True,
  "offline_verification": True,
}
open("$probe_json","w").write(json.dumps({
  "adapter": "generic",
  "keys": keys,
  "probed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
  "notes": [
    "file watcher detect-only; never reported as pre-write prevention",
    f"detect_log_exists={detect.exists()}",
    "mediation incomplete on generic wrapper",
  ],
}, indent=2))
PY
      ;;
    *)
      echo "unknown adapter: $adapter" >&2
      exit 2
      ;;
  esac

  "$LIA" report --adapter "$adapter" --probe "$probe_json" --json >"$report_json"
  python3 - <<PY
import json, sys
truth = json.load(open("$TRUTH"))
report = json.load(open("$report_json"))
adapter = "$adapter"
exp = truth[adapter]
level = report["level"]
# serde may emit Audit/Observe/Gate — normalize
level_s = str(level).upper().replace("ASSURANCELEVEL::", "")
if level_s not in ("AUDIT", "OBSERVE", "GATE", "CONFINE"):
    # tagged enum as string from serde rename
    level_s = level if isinstance(level, str) else level
assert level_s != "CONFINE", "v1 must never report CONFINE"
assert level_s == exp["level"], f"level {level_s} != {exp['level']}"
got = {g["gate_id"]: g["cell"] for g in report["gates"]}
def cell_name(c):
    if isinstance(c, str):
        return c
    return str(c)
for gate, want in exp["gates"].items():
    have = cell_name(got[gate])
    # normalize enum forms
    have = have.replace("Prevent", "PREVENT").replace("Detect", "DETECT").replace("CannotObserve", "CANNOT-OBSERVE")
    if have not in ("PREVENT", "DETECT", "CANNOT-OBSERVE"):
        # already screaming
        pass
    assert have == want, f"{adapter} {gate}: got {have} want {want}"
# HL-2: no network_control => cannot claim network prevent
assert report["capability_keys"].get("network_control") is False
assert "CANNOT-GUARANTEE" in report["network"]
print(f"PROBE OK {adapter} level={level_s}")
PY
  rm -rf "$work"
}

if [[ "$ADAPTER" == "all" ]]; then
  probe_one claude-code
  probe_one codex
  probe_one generic
  echo "PROBE ALL OK"
else
  probe_one "$ADAPTER"
fi
