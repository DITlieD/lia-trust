#!/usr/bin/env bash
# Gating smoke: fixture install → HARD fabricated-pass + OOS delete on Claude hook
# and Codex MCP → journal-verify → uninstall. Does not touch live ~/.claude/.codex.
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
REPO="$WORK/repo"
mkdir -p "$REPO/src"
echo "fn main() {}" >"$REPO/src/main.rs"

echo "== install (fixture) =="
"$LIA" install \
  --lia-home "$LIA_HOME" \
  --lia-bin "$LIA" \
  --claude-home "$CLAUDE_HOME" \
  --codex-home "$CODEX_HOME" \
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

echo "== Codex MCP HARD =="
REQ1='{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"run_test","arguments":{"claimed_pass":true}}}'
REQ2='{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_file","arguments":{"path":"/tmp/outside-lia-install-smoke-del"}}}'
"$LIA" mcp --config "$CFG" --journal "$DB" --secret-key-hex "$SECRET" --key-id smoke --adapter codex --request "$REQ1" >"$WORK/c1.out" || test $? -eq 2
"$LIA" mcp --config "$CFG" --journal "$DB" --secret-key-hex "$SECRET" --key-id smoke --adapter codex --request "$REQ2" >"$WORK/c2.out" || test $? -eq 2
python3 - <<PY
import json
for p in ["$WORK/c1.out","$WORK/c2.out"]:
  d=json.load(open(p))
  assert d["result"]["isError"] is True
print("codex deny ok")
PY

"$LIA" journal-verify "$DB"

echo "== status + uninstall =="
"$LIA" status --lia-home "$LIA_HOME" --claude-home "$CLAUDE_HOME" --codex-home "$CODEX_HOME" --json \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["claude_hook_installed"] and d["codex_mcp_installed"]'
"$LIA" uninstall --lia-home "$LIA_HOME" --claude-home "$CLAUDE_HOME" --codex-home "$CODEX_HOME" --json \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); assert not d["claude_hook_installed"] and not d["codex_mcp_installed"]'

echo "install_kernel_smoke OK"
