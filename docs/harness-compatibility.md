# Harness compatibility table

Kernel install wires **tool-boundary** mediation only. Assurance level is always
derived from capability keys (see `bench/assurance_truth.json` + `lia report`).

| Harness | Install path | Mediation surface | v1 level | PREVENT cells (when keys true) | CANNOT-OBSERVE |
|---------|--------------|-------------------|----------|--------------------------------|----------------|
| **Claude Code** CLI / IDE hooks | `lia install` → `~/.claude/settings.json` `hooks.PreToolUse` | PreToolUse command hook → `lia hook` | **GATE** | filesystem-scope, shell-irreversible, secret-output, journal-tamper on mapped tools; spawn-agent when Task/Agent match | Network/credential CONFINE; test/completion result observation; non-tool side effects; @-path reads outside tools; **child tools inside subagents** (unknown unless harness fires PreToolUse in child) |
| **Grok Build** (Claude-compat) | Same Claude hooks path (`~/.claude/settings.json` or Grok `compat.claude.hooks`); no separate Grok install required | PreToolUse → `lia hook --adapter claude-code` with **shared envelope normalize** (camelCase `toolName`/`toolInput`/`target_file`, `run_terminal_command`, `spawn_subagent`) | **GATE** | Same mapped cells as Claude on tools that fire the hook | Same as Claude; child PreToolUse **unknown**/partial (Stop→SubagentStop remap does not prove child tool mediation); unmediated tools (Grep, list_dir, many MCP) |
| **Codex** CLI / desktop MCP | `lia install` → `~/.codex/config.toml` `[mcp_servers.lia-trust]` | stdio MCP → `lia mcp` proxy tools | **GATE** | evidence-completeness, filesystem-scope, shell-irreversible, dependency-reality, secret-output, journal-tamper | Tools that never call the `lia-trust` server; network/credential CONFINE |
| **Generic / Devin-bridge** | `lia wrap` / `lia bench --harness generic` | Process wrap + optional watcher | **OBSERVE** / partial DETECT | journal-tamper PREVENT; shell often CANNOT-OBSERVE unless wrap captures | Complete mediation; CONFINE |
| **Generic (`--linux-confine`)** | Explicit digest-pinned `lia wrap` mode on supported Linux | user/mount/network/PID/UTS/IPC namespaces + recursive read-only host mount tree + Landlock write policy + credential FD broker | **CONFINE** only for attested per-run IP/path-write cells | IP egress, host/evidence path writes, one-shot declared credential delivery | Host filesystem reads; pathname Unix sockets; pre-opened FDs; same-uid/out-of-band processes; complete mediation |
| **TerminusLia (Harbor)** | Harbor agent wiring | Shell-irreversible only | **GATE** (shell) | shell-irreversible (+ fs when roots set) | ground/syco/ast/completion on that path |
| **Gemini CLI** | `lia install` → `~/.gemini/settings.json` `hooks.BeforeTool` | exact documented tool matcher → `lia hook --adapter gemini-cli` | **GATE** `[MEASURED]` | filesystem-scope, shell-irreversible, secret-output, journal-tamper on mapped tools | Unmatched/new tools; test/completion result observation; network/credential CONFINE; child tools unknown |
| **Cursor** | `lia install` → `~/.cursor/hooks.json` | fail-closed shell + MCP pre-hooks → `lia hook` | **GATE** | shell-irreversible and journal-tamper currently frozen | Unmapped tool semantics; network/credential CONFINE; all cells not probe-proven; no dedicated spawn hook |

## Operator visibility (V3)

```bash
lia status    # lists mediated vs known-unmediated tools for the install profile
lia doctor    # binary/hooks/roots/envelope self-test; exits non-zero on error checks
```

Default Claude/Grok matcher includes `Task|Agent` so spawn can be gated (`spawn_policy.allow`, default true = allow + signed journal). Full subagent PREVENT is **not** claimed: `subagent_visibility` stays false until a measured probe proves child PreToolUse.

## One-command install

```bash
cargo build -p lia-cli --release
./target/release/lia install --apply-live   # real harness homes
./target/release/lia status
./target/release/lia uninstall --apply-live
```

Fixture / CI (recommended):

```bash
./target/release/lia install \
  --lia-home "$PWD/.lia-fixture" \
  --claude-home "$PWD/.lia-fixture/claude" \
  --codex-home "$PWD/.lia-fixture/codex" \
  --gemini-home "$PWD/.lia-fixture/gemini" \
  --cursor-home "$PWD/.lia-fixture/cursor" \
  --lia-bin "$PWD/target/release/lia"
```

## VS Code / desktop

- **Claude Code IDE extension** reads the same user/project `settings.json` hooks
  schema as the CLI when the extension uses Claude Code’s hook pipeline.
- **Codex desktop** reads `~/.codex/config.toml` MCP servers (same pins as CLI).
- **Gemini CLI** uses the documented `BeforeTool` schema. Its current consumer-tier migration notice
  may affect product availability, so compatibility and service availability are separate claims.
- **Cursor** hook failures are fail-open by default; LIA explicitly installs `failClosed: true` on
  both mediated events.

Kernel does **not** inject editor UI chrome; it only wires the trust TCB at the
tool boundary. The optional generic Linux wrapper is a separate execution mode and does not raise
any hook/MCP adapter's assurance level.
