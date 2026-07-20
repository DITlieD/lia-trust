# LIA adapter contracts (pinned field names)

**Source of truth for machine-readable pins:** `crates/lia-adapters/contracts.json`  
**Pinned at:** 2026-07-18 (install fields extended 2026-07-20)

This document settles the harness field names LIA’s thin adapters rely on.
When Claude Code or Codex change their hook/MCP schema, update
`contracts.json` first, then this page.

## Kernel install surface

| CLI | Purpose |
|-----|---------|
| `lia install` | Wire Claude Code PreToolUse + Codex MCP; create `~/.lia-trust` state |
| `lia status` | Report whether hooks/MCP are installed |
| `lia uninstall` | Remove LIA wiring (journal/keys retained) |

Flags:

| Flag | Meaning |
|------|---------|
| `--lia-home` | State dir (default `$LIA_HOME` or `~/.lia-trust`) |
| `--claude-home` | Claude config dir (default `$CLAUDE_CONFIG_DIR` or `~/.claude`) |
| `--codex-home` | Codex config dir (default `$CODEX_HOME` or `~/.codex`) |
| `--dry-run` | Plan merge without writes |
| `--apply-live` | Required to modify real `~/.claude` / `~/.codex` |

**Marker:** `lia-trust-kernel` (hook `_lia_marker` / TOML comment). Uninstall removes only LIA entries.

## Claude Code (PreToolUse hook)

| Pin | Value |
|-----|-------|
| Settings file | `settings.json` under claude home |
| Hooks object key | `hooks` |
| Event | `PreToolUse` |
| Install matcher | `Bash\|Write\|Edit\|Read\|Delete\|MultiEdit` |
| Hook command type | `command` |
| Stdin event name field | `hook_event_name` |
| Tool fields | `tool_name`, `tool_input`, `cwd`, `session_id`, `tool_use_id` |
| Bash input | `command` |
| Write/Edit input | `file_path`, `content` |
| Decision stdout path | `hookSpecificOutput` |
| Decision fields | `hookEventName`, `permissionDecision`, `permissionDecisionReason` |
| Decision values | `allow`, `deny`, `ask`, `defer` |
| Block exit code | `2` |

Sources (external docs): [Claude Code hooks](https://code.claude.com/docs/en/hooks).

## Codex (MCP stdio proxy)

| Pin | Value |
|-----|-------|
| Config file | `config.toml` under codex home |
| MCP table | `[mcp_servers.<name>]` |
| LIA server name | `lia-trust` |
| Transport | stdio (`command` + `args`) |
| JSON-RPC | `2.0` |
| Methods | `tools/list`, `tools/call` |
| Call params | `name`, `arguments` |
| Result error flag | `isError` |

Proxy tools gated by LIA: `write_file`, `delete_file`, `shell`, `run_test`,
`complete_task`, `add_dependency`. Inspection tools are read-only:
`verify_run`, `inspect_receipts`, `explain_denial`, `show_policy`,
`show_adapter_capabilities`.

## Assurance (honest boundary)

| Adapter | Mediation | v1 level |
|---------|-----------|----------|
| Claude Code | Hook path for matched tools only | **GATE** (PREVENT where hook fires) |
| Codex | MCP proxy tools only | **GATE** |
| Generic wrap | Worktree + env allowlist; not complete mediation | **OBSERVE** / partial DETECT |

**CONFINE is forbidden in v1 claims** (`v1_forbid_confine: true`). Network,
credential broker, and non-tool side effects are **CANNOT-OBSERVE**.

## What Kernel is (product boundary)

Kernel = protocol + journal + Ed25519 receipts + seven gates + offline verify +
thin adapters at harness tool boundaries.

Not Kernel: commercial **Harness** / **Canvas** layers, claim extraction,
planning FSM, multi-agent recovery, process supervisor, or namespace CONFINE.
