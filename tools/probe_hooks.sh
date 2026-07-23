#!/usr/bin/env bash
# Probe LIA pretool envelopes (written under allowed_roots so the shell gate allows this file).
set -euo pipefail

LIA="${HOME}/.local/bin/lia"
WRAP="${HOME}/.lia-trust/bin/claude-pretool.sh"
CFG="${HOME}/.lia-trust/config.json"
JRN="${HOME}/.lia-trust/journal/default.db"
KEYF="${HOME}/.lia-trust/keys/signing.hex"
SECRET="$(tr -d '[:space:]' < "$KEYF")"

echo "=== version ==="
"$LIA" --version
echo "=== ls binaries ==="
ls -la "$LIA" "$WRAP"
echo "=== config ==="
cat "$CFG"
echo "=== wrap script ==="
cat "$WRAP"

probe() {
  local label="$1" mode="$2" json="$3"
  echo "===== $label ($mode) ====="
  local out ec
  if [[ "$mode" == wrap ]]; then
    set +e
    out=$(printf '%s' "$json" | "$WRAP" 2>&1)
    ec=$?
    set -e
  else
    set +e
    out=$(printf '%s' "$json" | "$LIA" hook --adapter claude-code \
      --config "$CFG" --journal "$JRN" --secret-key-hex "$SECRET" --key-id lia-install 2>&1)
    ec=$?
    set -e
  fi
  echo "exit=$ec"
  echo "out=$out"
}

A='{"hookEventName":"pre_tool_use","sessionId":"probe","cwd":"/home/lied","workspaceRoot":"/home/lied","permissionMode":"default","toolName":"read_file","toolInput":{"target_file":"/home/lied/teikoku/lia-trust/Cargo.toml"}}'
B='{"hookEventName":"pre_tool_use","sessionId":"probe","cwd":"/home/lied","workspaceRoot":"/home/lied","permissionMode":"default","toolName":"run_terminal_command","toolInput":{"command":"pwd"}}'
C='{"hookEventName":"pre_tool_use","sessionId":"probe","cwd":"/home/lied","workspaceRoot":"/home/lied","permissionMode":"default","toolName":"run_terminal_command","toolInput":{"command":"cd /home/lied/teikoku/lia-trust && git status -sb"}}'
D='{"hookEventName":"pre_tool_use","sessionId":"probe","cwd":"/home/lied","workspaceRoot":"/home/lied","permissionMode":"default","toolName":"run_terminal_command","toolInput":{"command":"cd /home/lied/teikoku/lia-trust && ls"}}'
E='{"hookEventName":"pre_tool_use","sessionId":"probe","cwd":"/home/lied","workspaceRoot":"/home/lied","permissionMode":"default","toolName":"run_terminal_command","toolInput":{"command":"ls -la /home/lied"}}'
F='{"hookEventName":"pre_tool_use","sessionId":"probe","cwd":"/home/lied","workspaceRoot":"/home/lied","permissionMode":"default","toolName":"run_terminal_command","toolInput":{"command":"'"$LIA"' --version"}}'
G='{"hookEventName":"pre_tool_use","sessionId":"probe","cwd":"/home/lied","workspaceRoot":"/home/lied","permissionMode":"default","toolName":"read_file","toolInput":{"target_file":"/home/lied/.lia-trust/config.json"}}'

probe A wrap "$A"
probe B wrap "$B"
probe C wrap "$C"
probe D wrap "$D"
probe Ddirect direct "$D"
probe E wrap "$E"
probe F wrap "$F"
probe G wrap "$G"
