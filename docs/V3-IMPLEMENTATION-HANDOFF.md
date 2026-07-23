# LIA Trust Kernel V3 implementation handoff

Durable execution record for `docs/V3-IMPROVEMENT-PLAN.md` → public `v0.3.0`.
Append-oriented: each milestone updates its section and the global ledger.

## Session identity and governing sources

- Session: `lia-trust-v3-20260724`
- Started: `2026-07-24`
- Repository: `/home/lied/teikoku/lia-trust`
- Plan authority: `docs/V3-IMPROVEMENT-PLAN.md`
- Baseline: `v0.2.2` / workspace `0.2.2`
- Status vocabulary: `SHIPPED`, `SHIPPED-LOCAL`, `PARTIAL`, `MISSING`, `DEFERRED`, `EXTERNAL-ONLY`
- Assurance rule: never invent observation; never upgrade PREVENT without measured probe

## Frozen execution order

1. M0 — recon & freeze (this document)
2. M1 — shared envelope normalize + parse signals
3. M2 — doctor + install polish + Grok compatibility row
4. M3 — spawn GATE
5. M4 — child mediation docs + linkage + probe keys
6. M5 — matcher profiles + MCP (stretch; may DEFER)
7. M6 — proof & public `0.3.0` release

No production-source edit may precede this M0 freeze commit.

## M0 — RECON / SCOPE_FROZEN

- State: `MILESTONE_COMMITTED` (docs freeze)
- Branch: `main`
- Baseline HEAD: post-`v0.2.2` + V3 plan commit
- Files: `docs/V3-IMPLEMENTATION-HANDOFF.md` (this file)

### Open decisions (resolved)

| # | Decision | Resolution |
|---|----------|------------|
| 1 | Native Grok adapter vs Claude-compat only | **Keep Claude-compat** as production path for Grok hooks; shared `envelope` module normalizes camelCase/snake_case. Thin native Grok JSON only if later required; not blocking 0.3.0. |
| 2 | Default matcher profile after V3 | **`default`** (current destructive/write/shell/read + Task/Agent for spawn). `broad` / `strict-mcp` are Ledger C stretch — DEFERRED if capacity forces. |
| 3 | Default spawn policy | **Allow spawn + signed journal** (`SPAWN_ALLOWED`). Policy can set `spawn_policy.allow=false` to deny. Compat-friendly default. |
| 4 | MCP unknown mutate fail-closed by default | **No** (too noisy). Strict profile DEFERRED with M5. |

### Harness event matrix (frozen)

| Harness | Parent tool event | Spawn event | Child PreToolUse | Envelope notes |
|---------|-------------------|-------------|------------------|----------------|
| Claude Code | `PreToolUse` | `Task` / `Agent` tools (when matcher hits) | **unknown** (depends on product; not claimed) | snake_case `tool_name` / `tool_input` / `file_path` |
| Grok Build (Claude compat) | `PreToolUse` via Claude hooks path | `spawn_subagent` → mapped spawn | **unknown** / partial (Stop→SubagentStop remap exists; child tools not proven) | camelCase `toolName` / `toolInput` / `target_file` |
| Cursor | `beforeShellExecution`, `beforeMCPExecution` | no dedicated spawn hook | **unknown** | shell command + MCP tool_name |
| Gemini CLI | `BeforeTool` | no dedicated spawn tool mapped | **unknown** | `run_shell_command` / `write_file` / `replace` / `read_file` |
| Codex | MCP stdio proxy tools | no Task spawn on proxy path | **n/a** (proxy tools only) | JSON-RPC tool names |

### Spawn schema (frozen)

- Wire tools → gate tool `spawn`: `Task`, `Agent`, `spawn_subagent`, `SubagentStart` (name aliases)
- Action kind: `spawn_agent` (`ActionKind::SpawnAgent`)
- Journal: `Event::GateVerdict` with `gate_id=spawn-agent`, reason `SPAWN_ALLOWED` or `SPAWN_DENIED`
- Config (`config.json`):

```json
"spawn_policy": {
  "allow": true
}
```

Default when absent: `allow: true` (journal on gate path when mediated).

### Matcher-profile defaults (frozen)

| Profile | Tools | Status for 0.3.0 |
|---------|-------|------------------|
| `default` | Bash\|Write\|Edit\|Read\|Delete\|MultiEdit\|NotebookEdit\|Task\|Agent | SHIPPED in M3 matcher expand |
| `broad` | + Glob/Grep read-scope, more MCP | DEFERRED (Ledger C) |
| `strict-mcp` | deny-unknown MCP mutate | DEFERRED (Ledger C) |

### Mediated vs known-unmediated (default Claude/Grok install)

**Mediated (matcher / proxy):** Bash, Write, Edit, Read, Delete, MultiEdit, NotebookEdit, Task, Agent (and Grok aliases: run_terminal_command, read_file, search_replace, write, delete_file, spawn_subagent).

**Known unmediated (examples):** Grep, Glob, list_dir, WebSearch, many MCP `server__tool` mutations, editor @-reads, unhooked binaries.

### Child mediation honesty (frozen)

- Full subagent PREVENT is **out of scope** unless probe proves child tools always hit LIA.
- `subagent_visibility` probe key remains **false** until measured.
- Parent/child linkage: when wire provides `session_id` / `parent_session_id` / `agent_id`, store on payload and journal detail — best-effort, not a security boundary.

### Ledger at M0 freeze

#### Ledger A — must for 0.3.0

| ID | Intent | Status at M0 |
|----|--------|--------------|
| V3-0 | Multi-envelope shared + fixtures | MISSING → M1 |
| V3-1 | ADAPTER_PARSE distinct from FS/SHELL | MISSING → M1 |
| V3-2 | `lia doctor` failing install | MISSING → M2 |
| V3-3 | Install does not shrink roots | SHIPPED (0.2.2); doctor surfaces → M2 |
| V3-4 | Spawn gateable + signed row | MISSING → M3 |
| V3-5 | Status mediated vs unmediated | MISSING → M2 |
| V3-6 | Grok first-class compatibility row | MISSING → M2 |
| V3-7 | Public 0.3.0 | MISSING → M6 |

#### Ledger B — partial OK

| ID | Intent | Status at M0 |
|----|--------|--------------|
| V3-10 | Child tools documented per harness | PARTIAL (matrix above) → M4 docs |
| V3-11 | Parent/child journal linkage when ids present | MISSING → M4 |
| V3-12 | `subagent_visibility` probe key | exists as false; honesty only → M4 |
| V3-13 | Full subagent PREVENT | DEFERRED / PARTIAL (no false claim) |

#### Ledger C — stretch

| ID | Intent | Status at M0 |
|----|--------|--------------|
| V3-20 | Matcher profiles broad/strict-mcp | DEFERRED (capacity) |
| V3-21 | MCP mutate policy | DEFERRED |
| V3-22 | Grep/list_dir opt-in FS-scope | DEFERRED |

#### Ledger D — external

| ID | Status |
|----|--------|
| V3-30 Live OAuth PREVENT | EXTERNAL-ONLY |
| V3-31 Second utility lane | DEFERRED |
| V3-32 Funding | EXTERNAL-ONLY |
| V3-33 Hosted IS-5 | PARTIAL (billing lock) |

### Blast radius

- Primary: `crates/lia-adapters` (envelope, install/doctor/status, claude_code, cursor, gemini)
- Secondary: `crates/lia-protocol` (ActionKind::SpawnAgent), `crates/lia-gates` (spawn-agent + reason codes + spawn_policy), `crates/lia-cli` (doctor, flags)
- Docs: harness-compatibility, V3 handoff, releases/v0.3.0.md
- Non-goals: process supervisor, CONFINE claim upgrades, live OAuth as release gate

### Next action

M1: extract shared envelope normalize; golden fixtures Claude/Grok/+1; ADAPTER_PARSE signal; adapters consume shared path.

---

## M1 — ENVELOPE

- State: `SHIPPED`
- Module: `crates/lia-adapters/src/envelope.rs` shared by Claude/Grok path
- Fixtures: Claude snake_case, Grok camelCase, Cursor/Gemini shell alias (`run_shell_command`)
- Parse signal: `AdapterError::Parse` → operator string `ADAPTER_PARSE: …` (distinct from FS_/SHELL_)
- Tests: unit + CLI `v3_doctor_spawn::grok_envelope_home_allow_oos_deny_via_hook`

## M2 — DOCTOR / INSTALL

- State: `SHIPPED`
- `lia doctor` exits non-zero on error checks (binary/manifest/roots/hooks/envelope)
- `lia status` lists mediated vs known-unmediated tools
- `--union-roots` merges explicit roots with prior config
- Reinstall preserves roots (0.2.2) retained
- Grok first-class row in `docs/harness-compatibility.md`
- Tests: install unit + CLI doctor smoke

## M3 — SPAWN GATE

- State: `SHIPPED`
- `ActionKind::SpawnAgent`, gate id `spawn-agent`, reasons `SPAWN_ALLOWED` / `SPAWN_DENIED`
- Config `spawn_policy.allow` (default true)
- Matcher includes `Task|Agent`; wire aliases Task/Agent/spawn_subagent/SubagentStart
- Signed journal via normal dispatch path; offline verify
- Tests: unit + CLI allow/deny + journal-verify

## M4 — CHILD MEDIATION

- State: `PARTIAL` (honest)
- Child PreToolUse documented per harness (yes/no/**unknown**) in handoff matrix + harness-compatibility
- Parent/child ids (`session_id`, `parent_session_id`, `agent_id`) captured on payload + spawn evidence/detail
- Probe keys added (default false): `grok_envelope`, `subagent_spawn_gate`, `subagent_child_tools`, `matcher_profile`; `subagent_visibility` remains false without measured child-tool proof
- Full subagent PREVENT **not** claimed

## M5 — MATCHER / MCP

- State: **DEFERRED** (Ledger C stretch)
- `broad` / `strict-mcp` matcher profiles and MCP mutate policy not shipped in 0.3.0
- Default profile expanded only for Task/Agent (spawn); document DEFERRED here

## M6 — RELEASE 0.3.0

- State: `SHIPPED` (local package + tag; remote push/release in same commit train)
- Workspace version `0.3.0`; `install.sh` VERSION_HINT; package_release artifacts
- Notes: `docs/releases/v0.3.0.md`
- Hosted IS-5: EXTERNAL/PARTIAL (billing) — non-blocking

### Ledger update post M1–M5

| ID | Status |
|----|--------|
| V3-0 | SHIPPED |
| V3-1 | SHIPPED |
| V3-2 | SHIPPED |
| V3-3 | SHIPPED |
| V3-4 | SHIPPED |
| V3-5 | SHIPPED |
| V3-6 | SHIPPED |
| V3-7 | SHIPPED |
| V3-10 | PARTIAL (docs) |
| V3-11 | SHIPPED (linkage when ids present) |
| V3-12 | SHIPPED (key exists; false by default) |
| V3-13 | DEFERRED / PARTIAL |
| V3-20..22 | DEFERRED |
