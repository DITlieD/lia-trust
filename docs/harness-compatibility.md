# Harness compatibility table

Kernel install wires **tool-boundary** mediation only. Assurance level is always
derived from capability keys (see `bench/assurance_truth.json` + `lia report`).

| Harness | Install path | Mediation surface | v1 level | PREVENT cells (when keys true) | CANNOT-OBSERVE |
|---------|--------------|-------------------|----------|--------------------------------|----------------|
| **Claude Code** CLI / IDE hooks | `lia install` → `~/.claude/settings.json` `hooks.PreToolUse` | PreToolUse command hook → `lia hook` | **GATE** | test-integrity, filesystem-scope, shell-irreversible, evidence, dependency, secret, journal (on matched tools) | Network/credential CONFINE; non-tool side effects; @-path reads outside tools |
| **Codex** CLI / desktop MCP | `lia install` → `~/.codex/config.toml` `[mcp_servers.lia-trust]` | stdio MCP → `lia mcp` proxy tools | **GATE** | Same seven gates on proxy tools | Same; tools that never call `lia-trust` server |
| **Generic / Devin-bridge** | `lia wrap` / `lia bench --harness generic` | Process wrap + optional watcher | **OBSERVE** / partial DETECT | journal-tamper PREVENT; shell often CANNOT-OBSERVE unless wrap captures | Complete mediation; CONFINE |
| **TerminusLia (Harbor)** | Harbor agent wiring | Shell-irreversible only | **GATE** (shell) | shell-irreversible (+ fs when roots set) | ground/syco/ast/completion on that path |
| Gemini CLI | — | POST-L6 | — | — | — |
| Cursor | — | POST-L6 | — | — | — |

## One-command install

```bash
cargo build -p lia-cli --release
./target/release/lia install --apply-live   # real ~/.claude + ~/.codex
./target/release/lia status
./target/release/lia uninstall --apply-live
```

Fixture / CI (recommended):

```bash
./target/release/lia install \
  --lia-home "$PWD/.lia-fixture" \
  --claude-home "$PWD/.lia-fixture/claude" \
  --codex-home "$PWD/.lia-fixture/codex" \
  --lia-bin "$PWD/target/release/lia"
```

## VS Code / desktop

- **Claude Code IDE extension** reads the same user/project `settings.json` hooks
  schema as the CLI when the extension uses Claude Code’s hook pipeline.
- **Codex desktop** reads `~/.codex/config.toml` MCP servers (same pins as CLI).

Kernel does **not** inject editor UI chrome; it only wires the trust TCB at the
tool boundary.
