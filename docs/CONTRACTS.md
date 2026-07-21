# LIA adapter contracts (pinned field names)

**Source of truth for machine-readable pins:** `crates/lia-adapters/contracts.json`  
**Pinned at:** 2026-07-22

This document settles the harness field names LIA’s thin adapters rely on.
When a supported harness changes its hook/MCP schema, update
`contracts.json` first, then this page.

## Kernel install surface

| CLI | Purpose |
|-----|---------|
| `lia install` | Wire Claude Code, Codex, Gemini CLI, and Cursor; create `~/.lia-trust` state |
| `lia status` | Report whether hooks/MCP are installed |
| `lia uninstall` | Remove LIA wiring (journal/keys retained) |

Flags:

| Flag | Meaning |
|------|---------|
| `--lia-home` | State dir (default `$LIA_HOME` or `~/.lia-trust`) |
| `--claude-home` | Claude config dir (default `$CLAUDE_CONFIG_DIR` or `~/.claude`) |
| `--codex-home` | Codex config dir (default `$CODEX_HOME` or `~/.codex`) |
| `--gemini-home` | Gemini config dir (default `$GEMINI_CLI_HOME` or `~/.gemini`) |
| `--cursor-home` | Cursor config dir (default `$CURSOR_HOME` or `~/.cursor`) |
| `--dry-run` | Plan merge without writes |
| `--apply-live` | Required to modify real user harness homes |

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
| Transport | stdio with **Content-Length** framing (not NDJSON) |
| Protocol version | `2024-11-05` |
| Lifecycle | `initialize` → `notifications/initialized` → `tools/list` / `tools/call` |
| JSON-RPC | `2.0` |
| Methods | `initialize`, `ping`, `tools/list`, `tools/call` |
| Call params | `name`, `arguments` |
| Result error flag | `isError` |
| Server info name | `lia-trust` |

Proxy tools gated by LIA: `write_file`, `delete_file`, `shell`, `run_test`,
`complete_task`, `add_dependency`. Inspection tools are read-only:
`verify_run`, `inspect_receipts`, `explain_denial`, `show_policy`,
`show_adapter_capabilities`.

## Gemini CLI (BeforeTool hook)

| Pin | Value |
|-----|-------|
| Settings file | `settings.json` under Gemini home |
| Event | `hooks.BeforeTool` |
| Matcher | `^(run_shell_command\|write_file\|replace\|read_file)$` |
| Input | common hook fields plus `tool_name` and `tool_input` |
| Output | `decision: allow|deny`, `reason` |
| Block exit code | `2` with reason on stderr |
| LIA timeout | 30,000 ms |

LIA ignores additive input fields for forward compatibility. A tool outside the installed matcher
is outside this adapter's mediation; if one reaches the handler directly, it is denied. Gemini's
current consumer-tier migration notice does not change the schema this compatibility adapter pins.
Source: [Gemini CLI hook reference](https://geminicli.com/docs/hooks/reference/).

## Cursor (shell and MCP hooks)

| Pin | Value |
|-----|-------|
| Hooks file | `.cursor/hooks.json` / configured Cursor home, version `1` |
| Events | `beforeShellExecution`, `beforeMCPExecution` |
| Shell input | `command`, `cwd`, `sandbox` |
| MCP input | `tool_name`, `tool_input`, optional `url` / `command` |
| Output | `permission: allow|deny|ask`, `user_message`, `agent_message` |
| Failure policy | `failClosed: true` on both installed hooks |

Mapped shell/MCP mutations reach the shared LIA gates. An unknown MCP tool returns `ask` so Cursor
must obtain explicit approval; it is not silently allowed. Additive input fields are ignored.
Source: [Cursor hooks](https://cursor.com/docs/hooks).

## Typed process contract

`lia process-contract-validate --contract ... --execution ... --journal ...` validates a
model-neutral `lia-process-contract-v1` document against signed journal receipts. A valid execution
must reference a same-run `process_contract_declared` receipt whose digest was journaled before every
referenced action. Completion then requires declared action kinds, required evidence receipts,
exact evidence-kind/digest agreement, assumption support, the unresolved-claim predicate, and a
same-run verified completion verdict. That terminal verdict signs a process-execution manifest
digest containing the contract digest, action/evidence receipt set, assumption support,
unresolved-claim set, and terminal assertion; a verdict from another contract cannot be reused.
Honest stop requires a declared condition, a same-condition incomplete/unsupported verdict, and
typed non-empty `tried` / `missing` / `route` unblock data.

The Kernel validates this boundary; it does not plan, decompose, repair, or decide the objective.

## Optional public and registry evidence

- `lia public-verify` delegates Sigstore bundle verification to an installed `cosign verify-blob`,
  requires `--expected-cosign-sha256`, pins certificate identity and OIDC issuer, records the
  artifact/bundle hashes and sizes, bounds output, and terminates the verifier process group on Unix
  before reaping on timeout. LIA does not reimplement Sigstore. Source:
  [Sigstore blob verification](https://docs.sigstore.dev/cosign/verifying/verify/).
- `lia registry-evidence` performs a bounded, no-shell `curl` lookup against the official sparse
  crates.io index or npm registry, rejects custom origins and redirects, requires a pinned client
  digest for live use, hashes the response, and supports age-bounded offline replay only when both
  response and cache-metadata digests are externally pinned. Sources:
  [Cargo registry index](https://doc.rust-lang.org/cargo/reference/registry-index.html),
  [npm registry](https://docs.npmjs.com/cli/v8/using-npm/registry/).

Executable digests and offline cache digests are trust roots supplied by the operator; pin them from
outside the agent-writable boundary. Same-UID replacement between checking and use remains a TOCTOU
limit until M5 isolation. Treat the live output as TLS-observed dependency evidence and journal or
bundle it outside the agent's writable boundary when durable authenticity matters.

## Assurance (honest boundary)

| Adapter | Mediation | v1 level |
|---------|-----------|----------|
| Claude Code | Hook path for matched tools only | **GATE** (PREVENT where hook fires) |
| Codex | MCP proxy tools only | **GATE** |
| Gemini CLI | BeforeTool path for the installed matcher only | **GATE** |
| Cursor | Shell/MCP hooks with `failClosed: true`; mapped tools only | **GATE** |
| Generic wrap | Worktree + env allowlist; not complete mediation | **OBSERVE** / partial DETECT |

**CONFINE is forbidden in v1 claims** (`v1_forbid_confine: true`). Network,
credential broker, and non-tool side effects are **CANNOT-OBSERVE**.

## What Kernel is (product boundary)

Kernel = protocol + journal + Ed25519 receipts + seven gates + offline verify +
thin adapters at harness tool boundaries.

Not Kernel: commercial **Harness** / **Canvas** layers, claim extraction,
planning FSM, multi-agent recovery, or automatic repair. Namespace/egress/credential confinement is
separate optional work and must not be inferred from these hook adapters.
