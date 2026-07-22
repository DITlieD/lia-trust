#!/usr/bin/env bash
# Gating smoke: fixture install → HARD fabricated-pass + OOS delete on Claude hook
# and Codex MCP → journal-verify → uninstall. All four harness homes are isolated.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
cargo build -p lia-cli --release
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
LIA="$TARGET_DIR/release/lia"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/lia-install-smoke-XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

LIA_HOME="$WORK/lia-home"
CLAUDE_HOME="$WORK/claude"
CODEX_HOME="$WORK/codex"
GEMINI_HOME="$WORK/gemini"
CURSOR_HOME="$WORK/cursor"
REPO="$WORK/repo"
mkdir -p "$REPO/src"
echo "fn main() {}" >"$REPO/src/main.rs"

echo "== install (fixture) =="
"$LIA" install \
  --lia-home "$LIA_HOME" \
  --lia-bin "$LIA" \
  --claude-home "$CLAUDE_HOME" \
  --codex-home "$CODEX_HOME" \
  --gemini-home "$GEMINI_HOME" \
  --cursor-home "$CURSOR_HOME" \
  --allowed-root "$REPO" \
  --json >"$WORK/install.json"

python3 - <<PY
import json
s=json.load(open("$CLAUDE_HOME/settings.json"))
assert any(
  h.get("_lia_trust") or any(x.get("_lia_trust") for x in h.get("hooks",[]))
  for h in s["hooks"]["PreToolUse"]
)
t=open("$CODEX_HOME/config.toml").read()
assert "[mcp_servers.lia-trust]" in t
g=json.load(open("$GEMINI_HOME/settings.json"))
assert g["hooks"]["BeforeTool"]
c=json.load(open("$CURSOR_HOME/hooks.json"))
assert c["version"] == 1 and c["hooks"]
print("wiring ok")
PY

# Point gate roots at repo
python3 - <<PY
import json
cfg={
  "allowed_roots": ["$REPO"],
  "home_dir": "/home/agent",
  "cwd": "$REPO",
  "protected_paths": [],
  "registry": {"serde": ["1.0.0"]},
  "env": {"HOME": "/home/agent"},
}
open("$LIA_HOME/config.json","w").write(json.dumps(cfg, indent=2))
PY

HOOK="$LIA_HOME/bin/claude-pretool.sh"
DB="$LIA_HOME/journal/default.db"
SECRET="$(tr -d '[:space:]' < "$LIA_HOME/keys/signing.hex")"
CFG="$LIA_HOME/config.json"

echo "== Claude installed-hook HARD =="
python3 -c 'import json,sys; print(json.dumps({"session_id":"smoke","cwd":sys.argv[1],"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo lia-fabricate-pass"},"tool_use_id":"t1"}))' "$REPO" \
  | "$HOOK" >"$WORK/fab.out" || test $? -eq 2
python3 -c 'import json; d=json.load(open("'"$WORK"'/fab.out")); assert d["hookSpecificOutput"]["permissionDecision"]=="deny"'

python3 -c 'import json,sys; print(json.dumps({"session_id":"smoke","cwd":sys.argv[1],"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/outside-lia-install-smoke"},"tool_use_id":"t2"}))' "$REPO" \
  | "$HOOK" >"$WORK/oos.out" || test $? -eq 2
python3 -c 'import json; d=json.load(open("'"$WORK"'/oos.out")); assert d["hookSpecificOutput"]["permissionDecision"]=="deny"'

echo "== Codex installed wrapper: Content-Length initialize → list → HARD deny =="
# Real Codex client path: long-lived stdio MCP with Content-Length framing.
# Drive the installed codex-mcp.sh (not bare --request one-shot).
MCP_WRAP="$LIA_HOME/bin/codex-mcp.sh"
test -x "$MCP_WRAP"
python3 - "$MCP_WRAP" "$WORK" <<'PY'
import json, os, subprocess, sys

wrap, work = sys.argv[1], sys.argv[2]

def frame(obj: dict) -> bytes:
    body = json.dumps(obj, separators=(",", ":")).encode()
    return f"Content-Length: {len(body)}\r\n\r\n".encode() + body

def read_frame(stdout) -> dict:
    headers = {}
    while True:
        line = stdout.readline()
        if not line:
            raise RuntimeError("EOF before MCP headers")
        if line in (b"\r\n", b"\n"):
            break
        if b":" in line:
            k, v = line.decode().split(":", 1)
            headers[k.strip().lower()] = v.strip()
    n = int(headers["content-length"])
    body = stdout.read(n)
    if len(body) != n:
        raise RuntimeError(f"short body want={n} got={len(body)}")
    return json.loads(body)

proc = subprocess.Popen(
    [wrap],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)
assert proc.stdin and proc.stdout

# 1) initialize
proc.stdin.write(frame({
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "lia-install-smoke", "version": "0"},
    },
}))
proc.stdin.flush()
init = read_frame(proc.stdout)
assert init.get("error") is None, init
assert init["result"]["serverInfo"]["name"] == "lia-trust", init
assert init["result"]["protocolVersion"] == "2024-11-05", init

# 2) notifications/initialized (no response)
proc.stdin.write(frame({"jsonrpc": "2.0", "method": "notifications/initialized"}))
proc.stdin.flush()

# 3) tools/list
proc.stdin.write(frame({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}))
proc.stdin.flush()
listed = read_frame(proc.stdout)
tools = [t["name"] for t in listed["result"]["tools"]]
assert "delete_file" in tools and "run_test" in tools, tools

# 4) HARD fabricated pass
proc.stdin.write(frame({
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {"name": "run_test", "arguments": {"claimed_pass": True}},
}))
proc.stdin.flush()
fab = read_frame(proc.stdout)
assert fab["result"]["isError"] is True, fab
assert fab["result"]["lia"]["allowed"] is False, fab

# 5) HARD OOS delete
proc.stdin.write(frame({
    "jsonrpc": "2.0",
    "id": 4,
    "method": "tools/call",
    "params": {
        "name": "delete_file",
        "arguments": {"path": "/tmp/outside-lia-install-smoke-del"},
    },
}))
proc.stdin.flush()
oos = read_frame(proc.stdout)
assert oos["result"]["isError"] is True, oos
assert oos["result"]["lia"]["allowed"] is False, oos

proc.stdin.close()
try:
    proc.wait(timeout=5)
except subprocess.TimeoutExpired:
    proc.kill()
    proc.wait(timeout=2)

open(os.path.join(work, "codex-framed-session.json"), "w").write(
    json.dumps({"initialize": init, "tools": tools, "fab": fab, "oos": oos}, indent=2)
)
print("codex framed initialize→list→HARD deny OK via installed wrapper")
PY

"$LIA" journal-verify "$DB"

echo "== status + uninstall =="
"$LIA" status \
  --lia-home "$LIA_HOME" \
  --claude-home "$CLAUDE_HOME" \
  --codex-home "$CODEX_HOME" \
  --gemini-home "$GEMINI_HOME" \
  --cursor-home "$CURSOR_HOME" \
  --json \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); assert all(d[k] for k in ("claude_hook_installed", "codex_mcp_installed", "gemini_hook_installed", "cursor_hooks_installed"))'
"$LIA" uninstall \
  --lia-home "$LIA_HOME" \
  --claude-home "$CLAUDE_HOME" \
  --codex-home "$CODEX_HOME" \
  --gemini-home "$GEMINI_HOME" \
  --cursor-home "$CURSOR_HOME" \
  --json \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); assert not any(d[k] for k in ("claude_hook_installed", "codex_mcp_installed", "gemini_hook_installed", "cursor_hooks_installed"))'

echo "install_kernel_smoke OK"
