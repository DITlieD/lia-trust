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
import json, pathlib, shutil, sqlite3, subprocess, time
work = pathlib.Path("$work")
repo = work / "repo"
repo.mkdir()
config = work / "config.json"
journal = work / "claude-journal.db"
secret = "44" * 32
config.write_text(json.dumps({
  "allowed_roots": [str(repo)],
  "home_dir": str(work / "home"),
  "cwd": str(repo),
  "protected_paths": [str(repo / ".lia")],
  "registry": {},
  "env": {"HOME": str(work / "home")},
}))

def verify_journal():
  assert journal.is_file(), "Claude hook did not create journal"
  subprocess.check_call(["$LIA", "journal-verify", str(journal)])

def deny(tool, tool_input, expected_reason):
  event = json.dumps({
    "hook_event_name": "PreToolUse",
    "tool_name": tool,
    "tool_input": tool_input,
    "cwd": str(repo),
  })
  proc = subprocess.run([
    "$LIA", "hook", "--adapter", "claude-code",
    "--config", str(config), "--journal", str(journal),
    "--secret-key-hex", secret, "--key-id", "probe-claude",
  ], input=event, text=True, capture_output=True, check=False)
  assert proc.returncode == 2, (proc.returncode, proc.stdout, proc.stderr)
  output = json.loads(proc.stdout)
  hook = output["hookSpecificOutput"]
  assert hook["permissionDecision"] == "deny", output
  assert expected_reason in hook["permissionDecisionReason"], output
  verify_journal()

deny("Write", {"file_path": "/etc/lia-probe-outside", "content": "x"}, "FS_OUT_OF_SCOPE")
deny("Bash", {"command": "rm -rf /"}, "SHELL_DESTRUCTIVE")
deny("Write", {
  "file_path": str(repo / "secret.txt"),
  "content": "sk-proj-" + "A" * 32,
}, "SECRET_IN_OUTPUT")

connection = sqlite3.connect(journal)
row_count = connection.execute("SELECT COUNT(*) FROM journal_rows").fetchone()[0]
connection.close()
assert row_count >= 3, row_count
tampered = work / "claude-tampered.db"
shutil.copy2(journal, tampered)
connection = sqlite3.connect(tampered)
connection.executescript("DROP TRIGGER IF EXISTS journal_rows_no_update; DROP TRIGGER IF EXISTS journal_rows_no_delete;")
connection.execute("UPDATE journal_rows SET row_hash = ? WHERE seq = 1", ("0" * 64,))
connection.commit()
connection.close()
tamper_check = subprocess.run(["$LIA", "journal-verify", str(tampered)], capture_output=True)
assert tamper_check.returncode != 0, "tampered Claude journal verified"

keys = {
  "pre_write_block": True,
  "post_write_receipt": True,
  "shell_pre_block": True,
  "shell_result_capture": False,
  "network_control": False,
  "credential_broker": False,
  "completion_gate": False,
  "subagent_visibility": True,
  "immutable_journal": True,
  "offline_verification": True,
}
open("$probe_json","w").write(json.dumps({
  "adapter": "claude-code",
  "keys": keys,
  "gate_cells": {
    "test-integrity": "CANNOT-OBSERVE",
    "evidence-completeness": "CANNOT-OBSERVE",
    "filesystem-scope": "PREVENT",
    "shell-irreversible": "PREVENT",
    "dependency-reality": "CANNOT-OBSERVE",
    "secret-output": "PREVENT",
    "journal-tamper": "PREVENT",
  },
  "probed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
  "notes": [
    "runtime probe: Claude hook denied out-of-scope write, destructive shell, and secret output",
    f"runtime probe: {row_count} signed rows verified; a mutated row failed offline verify",
    "test results, completion, and dependency actions are absent from PreToolUse mapping",
  ],
}, indent=2))
PY
      ;;
    codex)
      python3 - <<PY
import json, pathlib, shutil, sqlite3, subprocess, time
work = pathlib.Path("$work")
repo = work / "repo"
repo.mkdir()
config = work / "config.json"
journal = work / "codex-journal.db"
secret = "66" * 32
config.write_text(json.dumps({
  "allowed_roots": [str(repo)],
  "home_dir": str(work / "home"),
  "cwd": str(repo),
  "protected_paths": [str(repo / ".lia")],
  "registry": {},
  "env": {"HOME": str(work / "home")},
}))

def deny(name, arguments, gate_id, expected_reason):
  request = json.dumps({
    "jsonrpc": "2.0", "id": 1, "method": "tools/call",
    "params": {"name": name, "arguments": arguments},
  })
  proc = subprocess.run([
    "$LIA", "mcp", "--config", str(config), "--journal", str(journal),
    "--secret-key-hex", secret, "--key-id", "probe-codex", "--request", request,
  ], text=True, capture_output=True, check=False)
  assert proc.returncode == 2, (proc.returncode, proc.stdout, proc.stderr)
  output = json.loads(proc.stdout)
  result = output["result"]
  assert result["isError"] is True, output
  outcomes = result["lia"]["outcomes"]
  assert any(o["gate_id"] == gate_id and o["reason_code"] == expected_reason for o in outcomes), output
  assert result["lia"]["journal_receipts"], output
  subprocess.check_call(["$LIA", "journal-verify", str(journal)])

deny("write_file", {"path": "/etc/lia-probe-outside", "content": "x"}, "filesystem-scope", "FS_OUT_OF_SCOPE")
deny("shell", {"command": "rm -rf /"}, "shell-irreversible", "SHELL_DESTRUCTIVE")
deny("add_dependency", {"package": "lia-probe-not-in-registry"}, "dependency-reality", "DEP_NOT_FOUND")
deny("complete_task", {"modified_paths": ["src/lib.rs"], "has_test_result": False}, "evidence-completeness", "EVIDENCE_INCOMPLETE")
deny("write_file", {
  "path": str(repo / "secret.txt"),
  "content": "sk-proj-" + "B" * 32,
}, "secret-output", "SECRET_IN_OUTPUT")

connection = sqlite3.connect(journal)
row_count = connection.execute("SELECT COUNT(*) FROM journal_rows").fetchone()[0]
connection.close()
assert row_count >= 5, row_count
tampered = work / "codex-tampered.db"
shutil.copy2(journal, tampered)
connection = sqlite3.connect(tampered)
connection.executescript("DROP TRIGGER IF EXISTS journal_rows_no_update; DROP TRIGGER IF EXISTS journal_rows_no_delete;")
connection.execute("UPDATE journal_rows SET row_hash = ? WHERE seq = 1", ("0" * 64,))
connection.commit()
connection.close()
tamper_check = subprocess.run(["$LIA", "journal-verify", str(tampered)], capture_output=True)
assert tamper_check.returncode != 0, "tampered Codex journal verified"

keys = {
  "pre_write_block": True,
  "post_write_receipt": True,
  "shell_pre_block": True,
  "shell_result_capture": False,
  "network_control": False,
  "credential_broker": False,
  "completion_gate": True,
  "subagent_visibility": False,
  "immutable_journal": True,
  "offline_verification": True,
}
open("$probe_json","w").write(json.dumps({
  "adapter": "codex",
  "keys": keys,
  "gate_cells": {
    "test-integrity": "CANNOT-OBSERVE",
    "evidence-completeness": "PREVENT",
    "filesystem-scope": "PREVENT",
    "shell-irreversible": "PREVENT",
    "dependency-reality": "PREVENT",
    "secret-output": "PREVENT",
    "journal-tamper": "PREVENT",
  },
  "probed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
  "notes": [
    "runtime probe: Codex MCP denied filesystem, shell, dependency, completion, and secret fixtures",
    f"runtime probe: {row_count} signed rows verified; a mutated row failed offline verify",
    "MCP tool proxy intercepts only tools/call routed through lia mcp; it does not execute tests",
  ],
}, indent=2))
PY
      ;;
    generic)
      python3 - <<PY
import hashlib, json, time, os, pathlib, shutil, sqlite3, subprocess, tempfile
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
wrap_raw = subprocess.check_output([
  "$LIA", "wrap",
  "--repo", str(repo),
  "--evidence-dir", str(evidence),
  "--config", str(cfg_path),
  "--secret-key-hex", secret,
  "--key-id", "probe",
  "--", str(agent),
], cwd=str(repo), text=True)
wrap_report = json.loads(wrap_raw)
assert evidence.exists()
assert not str(evidence.resolve()).startswith(str((evidence / "worktree-" ).resolve()) if False else str(repo.resolve()))
journal = pathlib.Path(wrap_report["journal_path"])
# journal path is outside worktree writable area by construction
wt = list(evidence.glob("worktree-*"))
assert wt, "worktree missing"
assert journal.parent == evidence
assert journal.is_file(), "generic journal missing"
subprocess.check_call(["$LIA", "journal-verify", str(journal)])
assert wrap_report.get("final_diff_sha256"), wrap_report
worktree = pathlib.Path(wrap_report["worktree"])
touched = worktree / "touched.txt"
assert touched.read_text() == "hi\n", "wrapped mutation missing from reported worktree"

def snapshot(root):
  return {
    str(path.relative_to(root))
    for path in root.rglob("*")
    if path.is_file()
  }

hasher = hashlib.sha256()
for relative in sorted(snapshot(worktree) | snapshot(repo)):
  hasher.update(relative.encode())
  after = (worktree / relative).read_bytes() if (worktree / relative).is_file() else b""
  before = (repo / relative).read_bytes() if (repo / relative).is_file() else b""
  if after != before:
    hasher.update(after)
assert hasher.hexdigest() == wrap_report["final_diff_sha256"], "generic diff digest mismatch"
connection = sqlite3.connect(journal)
row_count = connection.execute("SELECT COUNT(*) FROM journal_rows").fetchone()[0]
connection.close()
assert row_count >= 3, row_count
tampered = pathlib.Path("$work") / "generic-tampered.db"
shutil.copy2(journal, tampered)
connection = sqlite3.connect(tampered)
connection.executescript("DROP TRIGGER IF EXISTS journal_rows_no_update; DROP TRIGGER IF EXISTS journal_rows_no_delete;")
connection.execute("UPDATE journal_rows SET row_hash = ? WHERE seq = 1", ("0" * 64,))
connection.commit()
connection.close()
tamper_check = subprocess.run(["$LIA", "journal-verify", str(tampered)], capture_output=True)
assert tamper_check.returncode != 0, "tampered generic journal verified"
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
  "gate_cells": {
    "test-integrity": "CANNOT-OBSERVE",
    "evidence-completeness": "CANNOT-OBSERVE",
    "filesystem-scope": "DETECT",
    "shell-irreversible": "CANNOT-OBSERVE",
    "dependency-reality": "CANNOT-OBSERVE",
    "secret-output": "CANNOT-OBSERVE",
    "journal-tamper": "PREVENT",
  },
  "probed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
  "notes": [
    "runtime probe: wrapped mutation exists and independently recomputed final-diff digest matches",
    "file watcher is supplemental; filesystem cell is final-diff DETECT, never pre-write prevention",
    f"runtime probe: final diff captured and {row_count} signed rows verified",
    "runtime probe: a mutated generic journal row failed offline verify",
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
