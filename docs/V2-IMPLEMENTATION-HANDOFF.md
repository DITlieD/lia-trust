# LIA Trust Kernel V2 implementation handoff

This is the durable execution record for reconciling and implementing the locally actionable
V2 / POST-L6 scope. It is append-oriented: each milestone updates its own section and the global
ledger. A green unit suite alone is not completion; each public behavior needs a compiled entrypoint,
signed journal evidence where the boundary supports it, separate-process verification, and an honest
capability-derived assurance statement.

## Session identity and governing sources

- Session: `lia-trust-v2-20260722`
- Started: `2026-07-22T03:35:10+09:00`
- Repository: `/home/lied/teikoku/lia-trust`
- Original intent authority: `/home/lied/teikoku/elai/workflow/reasoning/LIA-TRUST-KERNEL-PLAN.md`
- Live implementation authority: this repository at the recorded HEAD
- Live next-version record: `docs/roadmap.md`
- Backlog authorities: `bench/harbor/results/lia-improvement-backlog.json` and
  `bench/harbor/results/lia-41-item-scores.json`
- Status vocabulary: `SHIPPED`, `PARTIAL`, `MISSING`, `DOC-ONLY`,
  `OBSOLETE-BY-LATER-DESIGN`, `EXTERNAL-ONLY`, `BLOCKED`
- Assurance rule: static readiness is not runtime success; recorded adapters are not live agents;
  process liveness is not useful-work evidence.

## Frozen execution order

1. M0 — reconcile requirements, freeze scope and blast radius.
2. M1 — explicit policy-bounded in-root recursive cleanup without weakening hard denials.
3. M2 — close production-path trust wiring and durable evidence gaps.
4. M3 — telemetry, bounded recovery, performance, and journal lifecycle.
5. M4 — typed process contracts, Gemini/Cursor adapters, and optional public verification.
6. M5 — locally implementable Linux confinement, egress, and credential/evidence isolation.
7. M6 — independent proof, conformance, benchmarks, claims reconciliation, and completion audit.

No production-source edit may precede the M0 audit and commit. Each later milestone starts with
failing tests/fixtures, then implementation, then an auditor verdict, then a handoff update and commit.

## M0 — RECON / SCOPE_FROZEN

- State: `MILESTONE_COMMITTED`
- Timestamp: `2026-07-22T03:44:35+09:00`
- Branch: `main`
- Starting HEAD: `7794cfed4f841fcad3229cb0a5563520eb7471e9`
- Worktree before edit: clean (`git status --porcelain=v1` returned no rows)
- Pre-existing overlapping user changes: none
- Files changed: `docs/V2-IMPLEMENTATION-HANDOFF.md`
- Dependencies added: none
- Audit status: first independent audit `BLOCK` (three discrepancies), second `BLOCK` (one remaining
  inconsistency), final independent audit `PASS` with 6/6 structural checks, no warnings, and no
  regressions. Rust suite intentionally skipped for docs-only M0.
- Auditor commands: `git status --porcelain=v1`; `git branch --show-current`; `git rev-parse HEAD`;
  `git tag --list`; ledger-ID comparison script; `python3 -m py_compile
  bench/harbor/agents/terminus_lia.py`; source `rg`/`sed`/`nl`; evidence-path `test -e` checks.
- Off-agent evidence: independent `m0_auditor` verdict, transcribed into this M0 section; no durable
  report file was emitted by the auditor.
- Assurance ceiling: unchanged V1 `GATE` at visible tool boundaries; no CONFINE or complete mediation
- Blocker: none
- Next action: begin M1 with RED fixtures before production implementation
- Milestone commit: `dcdf2528877db530484d6f83abe95bf0806ac5cc`

### Direct answer at the M0 starting HEAD: context-dependent destructive commands

The live implementation does **not** currently support context-dependent recursive deletion.
`crates/lia-gates/src/shell.rs::check_shell_irreversible` calls `is_destructive` before filesystem
scope evaluation, and `is_destructive` returns true for every `rm` carrying recursive and force
flags. Therefore `rm -rf ./target` is denied as `SHELL_DESTRUCTIVE` even when `./target` is under an
allowed root. `docs/shell-rm-policy.md` explicitly documents this V1 behavior and describes an
explicit risk-tiered allowlist only as a future design. The V2 behavior belongs in M1 and must be
policy-owned, target-specific, normalized, fail-closed, and receipt-verifiable; the model never gets
to decide that a deletion is legitimate.

## Requirement ledger A — original plan units

| ID | Intended behavior | Current evidence | Status | Acceptance evidence | Target |
|---|---|---|---|---|---|
| L0 | Protocol plus append-only signed journal and offline verify | `lia-protocol`, `lia-journal`, `lia-verify`; Ed25519 rows and bundle verifier | SHIPPED | current workspace tests; CLI journal/verify round trip; tamper fixture | M6 reproof |
| L0b | Dogfood wiring/freeze/dead-code CI | `tools/lia_wire_check`, `tools/lia_gate_freeze`, `.github/workflows/wire.yml` | SHIPPED | wire/freeze scripts and CI definitions pass at final HEAD | M6 reproof |
| L1 | Frozen rules-as-data, stable reasons, fail-closed policy | `lia-policy`; policy and gate reason-code locks | SHIPPED | policy/golden tests plus malformed/missing-policy CLI cases | M6 reproof |
| L2 | Seven deterministic core gates | seven `lia-gates` modules and dispatch mapping | SHIPPED | adversarial fixtures, compiled CLI, journal/verify proof for each class | M2/M6 reproof |
| L3 | Thin adapters plus capability-derived assurance | Claude hook, Codex MCP proxy, generic wrap exist; Gemini/Cursor absent | PARTIAL | adapter conformance and probe-derived report for every shipped adapter | M4 |
| L4 | Ground, syco, AST, taint with production consumers | crates/CLI/live bench exist; AST/taint helper is not on normal write dispatch; Terminus is shell-only | PARTIAL | real adapter reachability with signed result or claims corrected to cannot-observe | M2 |
| L5 | Three-arm trust benchmark and utility companion | recorded corpora and scorecards exist; some live/utility lanes remain partial/deferred | PARTIAL | current frozen corpus replay, separated recorded/live metrics, optional external lanes labeled | M6 |
| L6 | Conformance/action/docs/release pack | docs, action, conformance suite, README and `v0.1.0` tag exist; no prebuilt release artifact, sample-repo Action bundle, or different-machine verification evidence is present | PARTIAL | tagged prebuilt release, sample-repo Action bundle, and separately built/different-machine verification proof, or exact external blocker | M6 |
| L7 | Post-release funding applications with claims discipline | `docs/programs.md`; no application action authorized | EXTERNAL-ONLY | local truthful templates/lint complete; actual submission remains owner/third-party action | M6 record |

## Requirement ledger B — 41-item live improvement backlog

The prior `DONE`/`DONE-DOC` labels are treated as historical evidence, not proof that later-version
behavior is shipped. Acceptance below is re-evaluated at the final HEAD.

| ID | Intended behavior | Current implementation evidence | Status | Exact acceptance evidence | Target |
|---|---|---|---|---|---|
| P0-1 | real Terminus workspace roots | `_workspace_roots` uses task mounts/env roots | SHIPPED | Terminus decision fixture has zero benign OOS denials | M6 |
| P0-2 | reason-specific denial UX | hard/soft reason sets and recovery text in `terminus_lia.py` | SHIPPED | positive hard deny and soft recovery fixture | M3 reproof |
| P0-3 | cap identical deny loops | per-command/reason counters and `LIA_DENY_CAP` | SHIPPED | repeated-denial fixture stops forwarding and emits cap | M3 reproof |
| P0-4 | quote-aware substitution detection | expansion tests and quote-aware scanner | SHIPPED | quoted backticks allow; executable substitution denies | M1/M6 |
| P0-5 | lexical traversal normalization | `normalize_lexical` plus scope gate | SHIPPED | traversal/out-of-root property cases | M1/M6 |
| P0-6 | durable Harbor journal | optional durable path exists, but fallback journal is temporary and failures can fail open | PARTIAL | default per-trial durable owner/lifecycle plus separate verifier | M2/M3 |
| P0-7 | per-trial reason telemetry | `deny_by_reason` output histogram | SHIPPED | integration fixture contains stable reason histogram | M3 |
| P1-1 | expanded destructive coverage | destructive pattern pack in `shell.rs` | SHIPPED | hard irreversible regression fixtures remain denied | M1/M6 |
| P1-2 | modern secret patterns | expanded patterns in `secret.rs` | SHIPPED | adversarial secret pack and clean controls | M6 |
| P1-3 | meaningful journal tamper probe | real verifier plus broken-chain fixtures | SHIPPED | event-byte/hash/signature mutation all fail offline | M6 |
| P1-4 | destructive class parity in live arm | frozen trust corpus includes destructive class | SHIPPED | current scorecard class count/catch without pooling lanes | M6 |
| P1-5 | 20-command destructive fixture pack | shell tests/bench fixtures | SHIPPED | all hard fixtures deny and benign controls allow | M1/M6 |
| P1-10 | ground/syco wiring honesty | live trust loop wired; Terminus explicitly shell-only | PARTIAL | supported adapters consume gates, unsupported ones say cannot-observe | M2 |
| P1-11 | AST write admission | helper and Harbor fixture exist; normal adapter writes do not invoke it | PARTIAL | real adapter write path blocks AST fixture and journals verdict | M2 |
| P1-12 | taint admission | helper/CLI and corpus exist; normal adapter dispatch has no taint payload | PARTIAL | typed adapter action reaches taint gate and journals verdict | M2 |
| P1-13 | Claude/Codex measurement | recorded-adapter PREVENT measured; live OAuth agents unmeasured | PARTIAL | current recorded replay; live remains explicit external gate absent credentials | M6 |
| P1-14 | completion admission | `CompleteTask` dispatch exists in Codex proxy; not every harness exposes completion | PARTIAL | real supported completion entrypoint denies missing evidence; capability cells honest | M2 |
| P1-20 | utility token tax bound | TB2 subset meets bound; Claw full rerun deferred | PARTIAL | local regression proof; external/full rerun precisely labeled | M3/M6 |
| P1-21 | Claw contingency | `claw-utility-contingency.md` | SHIPPED | claims lint and document consistency | M6 |
| P1-22 | policy-approved in-root `rm -rf` | V2 `cleanup_policy` exact-target gate, compiled CLI test, signed journal and offline verifier | SHIPPED | 4/4 cleanup CLI tests, 17/17 shell fixtures, hard-denial regression matrix | M1 complete; M6 reproof |
| P2-1 | bounded external/process timeouts | some scripts/timeouts exist; Terminus gate spawn has no timeout | PARTIAL | explicit timeout/cancellation result and fail-closed fixture | M3 |
| P2-2 | denial telemetry | reason histograms in collector/output | SHIPPED | stable structured counter fixture | M3 |
| P2-3 | lower gate-process overhead | in-memory decision memo only; no service/daemon | PARTIAL | measured cached path plus correctness and lifecycle proof | M3 |
| P2-4 | bounded shareable journal | `shareable_anchors` and verifier support | SHIPPED | truncated anchored bundle verifies; tamper fails | M3/M6 |
| P2-5 | duplicate-command memo | `_decision_memo` | SHIPPED | duplicate fixture avoids respawn; invalidation rules proven | M3 |
| P2-10 | L6 docs pack | required public documents now present | SHIPPED | claims lint and file checklist | M6 |
| P2-11 | assurance drift prevention | capability-derived report exists, but probes assert capabilities the production paths do not prove: generic wrap discards its `RunContext`, and Claude PreToolUse cannot observe shell results or completion | PARTIAL | probes derive only runtime-proven cells; generic journal exists/verifies; Claude result/completion cells remain false without an observing boundary | M2/M5/M6 |
| P2-12 | IS-5 publish path | local action definition, local smoke, and v0.1.0 tag only; no release workflow/prebuilt artifact/sample-repo bundle/different-machine verification evidence | PARTIAL | local prerequisites pass and missing remote/cross-machine proof is either obtained or recorded as an exact external gate | M6 |
| P2-13 | license/advisory checks | `deny.toml`, license policy/scripts | SHIPPED | current dependency audit/license checks | M6 |
| P2-14 | wire coverage | wire map/check/action | SHIPPED | final wire checker | M6 |
| P2-15 | claims separation | `claims.json` separates recorded/live/utility | SHIPPED | claims lint and manual final reconciliation | M6 |
| P2-16 | ground symbol depth | improved symbol matching and fixtures | SHIPPED | positive/negative symbol cases | M6 |
| P2-17 | HL-4 wrapper digest on Terminus tests | helper observation exists; Terminus never identifies/runs test gate | PARTIAL | applicable command result becomes wrapper observation and signed test verdict | M2 |
| P3-1 | second free-model utility lane | local driver exists; actual second-model execution is deferred | PARTIAL | local lane configuration validated; run remains explicitly gated on external model/service availability and cost | M6 |
| P3-2 | Claw companion signal | documented companion metric | SHIPPED | claims remain non-product and non-pooled | M6 |
| P3-3 | AST/taint corpus classes | corpus and runner classes exist | SHIPPED | current by-class replay | M2/M6 |
| P3-4 | network/egress confinement | no backend; capability false | MISSING | supported Linux backend proves egress deny; unsupported hosts fail closed/honest | M5 |
| P3-5 | Gemini CLI and Cursor adapters | roadmap/docs only; no production modules | MISSING | adapters, installers/launchers, conformance, probes, receipts | M4 |
| P3-6 | full typed process contract | completion half only; full schema and validator absent | MISSING | versioned contract schema, state transitions, validator, CLI/adapter proof | M4 |
| P3-7 | MCP inspection/live agent PREVENT | inspection UX and recorded adapters shipped; live OAuth not run | PARTIAL | inspection conformance; live portion remains exact external credential gate | M4/M6 |
| P3-8 | funding applications | process documentation only by design | EXTERNAL-ONLY | local claims-clean prerequisites; no submission in this task | M6 record |

## Requirement ledger C — V2 / POST-L6 and threat-model promises

| Source | Promise | Current evidence | Status | Exact acceptance evidence | Target |
|---|---|---|---|---|---|
| `docs/shell-rm-policy.md` | explicit policy-approved in-root cleanup | V2 schema and deterministic gate are live with receipt-backed CLI coverage | SHIPPED | M1 independent PASS; final-head replay in M6 | M1 complete; M6 reproof |
| roadmap P3-1 | second utility model lane | lane machinery exists, execution deferred | PARTIAL | validate local configuration; record external model/service/cost execution gate | M6 |
| roadmap P3-4 | network/egress CONFINE | capability key false, no backend | MISSING | local Linux network namespace/deny proof where supported | M5 |
| roadmap P3-5 | Gemini CLI adapter | no module/contract/conformance case | MISSING | real supported hook/proxy entrypoint plus signed deny | M4 |
| roadmap P3-5 | Cursor adapter | no module/contract/conformance case | MISSING | real supported hook/proxy entrypoint plus signed deny | M4 |
| roadmap P3-6 | full typed process-contract validator | evidence-completeness only | MISSING | schema, transition validator, reason codes, CLI/adapter proof | M4 |
| roadmap P3-7 | live Claude/Codex agent PREVENT | recorded lanes only | PARTIAL | local conformance complete; live run requires owner OAuth/service | M6 |
| roadmap P3-8 | funding applications | docs only, intentionally post-release | EXTERNAL-ONLY | no external submission; claims-clean template/state only | M6 |
| roadmap P3-9 / HL-5 | optional cosign public-log verification | offline Ed25519 only | MISSING | optional executable verifier with timeout and fixture/mock; live log external | M4 |
| roadmap P3-10 | Linux namespace CONFINE backend | absent | MISSING | supported-host namespace/process proof and honest fallback | M5 |
| threat model | signing identity outside agent principal | key file shares user identity today | PARTIAL | brokered FD/process boundary and file-permission checks; OS principal separation external | M5 |
| threat model | credential broker | capability false, env allowlist still includes credential-adjacent vars | MISSING | secret-minimized child environment and scoped credential delivery/expiry | M5 |
| threat model | live registry dependency evidence | fixture snapshots only | MISSING | bounded client, pinned response evidence, offline/cache semantics, timeout | M4 |
| threat model | persistent evidence outside writable worktree | generic wrap reserves an external journal path but discards its `RunContext` and emits no row; hook install shares user home | PARTIAL | per-adapter production journal, ownership/lifecycle and tamper proof; OS principal separation honest | M2/M5 |

## Discrepancy map

| Claim/design record | Live behavior | Resolution |
|---|---|---|
| P1-22 `DONE-DOC` can look complete | no context-dependent recursive delete exists | reclassify as DOC-ONLY and implement in M1 |
| “41/41 done” includes documentation-only deferrals | six security/product behaviors remain absent or partial | preserve historical score but use this implementation ledger for V2 |
| L4 components exist | existence/CLI reachability is broader than normal adapter enforcement | wire supported production paths or lower capability claims in M2 |
| Terminus has a durable-journal option | default fallback can be temporary and error paths fail open | make lifecycle explicit and fail closed in M2/M3 |
| Generic wrap reports a journal path and its probe asserts immutable/offline evidence | `generic::wrap` constructs then discards `RunContext`; no journal row is produced | create and verify production-path journal evidence in M2; lower probe cells until proven |
| Claude install probe asserts shell-result capture and completion gate | PreToolUse observes neither command results nor a completion event | set cells false unless a separately verified observing boundary is added in M2/M6 |
| V1 assurance intentionally caps at GATE | V2 roadmap asks for CONFINE | add an opt-in, probe-proven backend; never raise unsupported adapters in M5 |
| recorded Claude/Codex lanes say PREVENT | no live OAuth agent measurement | retain recorded label; external live gate stays open in M6 |
| generic wrap says isolated worktree | it is not process/network confinement | preserve current honesty; only a namespace backend may claim CONFINE |
| L6/P2-12 historical completion labels | local tag/action/smoke do not prove prebuilt release, sample-repo bundle, or different-machine verification | reclassify PARTIAL; obtain local proof and record remote/cross-machine gate in M6 |

## Frozen blast-radius and compatibility map

| Surface | Expected change | Compatibility obligation |
|---|---|---|
| `lia-gates::GateConfig` | versioned cleanup approvals and policy inputs | serde defaults preserve existing config files; missing approval fails closed |
| shell/filesystem gates | structured destructive classification and canonical target checks | existing hard reason meanings remain stable; add new reason codes explicitly |
| protocol/journal rows | process/approval/confinement events if needed | append-compatible event variants; old bundles still verify |
| policy schema | explicit target-scoped cleanup rule | old rules remain valid; frozen hash continues to bind exact source bytes |
| CLI | approval/process/adapters/confinement/public-verify commands | boundary validation, nonzero fail-closed exits, machine-readable JSON |
| Claude/Codex adapters | AST/taint/test/completion reachability where observable | do not claim observation for unavailable hook events |
| Gemini/Cursor adapters | new thin mappings/install surfaces | use documented native boundary only; generic wrapper fallback labeled OBSERVE |
| journal/verify | new verdicts/receipts and lifecycle controls | separate-process recomputation; no secret in shareable bundles |
| Harbor Terminus adapter | durable journal, timeout, test observation, cache lifecycle | no fail-open on missing binary, timeout, malformed output, or journal failure |
| conformance/fixtures | new adapters, cleanup/process/confine cases | frozen truths versioned and negative controls retained |
| assurance/contracts | capability keys and rollup for optional backend | runtime probe is sole source of CONFINE; V1 reports remain valid |
| docs/claims/roadmap | status and assurance reconciliation | no current number added without measured/external tag |
| benchmark consumers | new classes and latency/lifecycle metrics | recorded/live and trust/utility remain separated |

### Mandatory failure and lifecycle cases

- Null/missing/malformed policy, unknown fields, empty approvals, expired approvals, target mismatch,
  path traversal, symlink targets and symlink swaps, tilde/env/glob/quote/heredoc/nested-shell and
  command-substitution ambiguity all fail closed.
- Filesystem errors, unavailable roots, oversized commands/policies/events, journal open/write/fsync
  failures, interrupted or timed-out child processes, malformed adapter messages, dropped connections,
  unavailable namespaces, missing kernel tools/capabilities, failed egress-rule installation, and
  unsupported harness events yield stable errors and do not silently allow.
- Approval tokens are created by an explicit user-facing command, bound to normalized target, command
  class, policy hash, working directory, run identity, issuer, and expiry; consumed once unless the
  policy explicitly says bounded multi-use; then expired and auditable.
- Journals/evidence are created outside the child-writable tree, owned by the wrapper/broker, synced
  before allow is returned, rotated by bounded size/age, and recoverable through verified anchors.
- Signing keys and scoped credentials are created by the wrapper/broker, never written into shareable
  artifacts, permission-checked, rotated/expired explicitly, omitted from child env by default, and
  treated as only same-UID isolation unless a separate principal is actually configured.
- Child processes, watchers, namespace helpers, sockets, temporary worktrees, egress rules, and bench
  runs have explicit ownership, timeouts, cancellation, cleanup, and stale-resource recovery.

## Milestone templates (updated at each boundary)

### M1 — context-dependent recursive cleanup

- State: `MILESTONE_AUDITING` (independent PASS; commit pending)
- Timestamp: `2026-07-22T04:01:49+09:00`
- Starting HEAD: `40fdaf4eb60f2279a0e87f1c2075b861ed1b0429`
- Requirements: P1-22 and shell/path portions of P0-4/P0-5/P1-1/P1-5
- Completed behavior under audit: versioned `cleanup_policy` in gate config; exact normalized target
  matching; stable approved/approval-required/out-of-scope/protected/ambiguous reasons; hard root,
  home-wide, allowed-root, substitution, compound/nested shell, glob, unknown-env and symlink defenses.
- Architectural decision: preserve `SHELL_DESTRUCTIVE` for true irreversible targets and existing
  destructive classes; only a single top-level `rm` with recursive+force flags can enter the explicit
  cleanup policy path. Policy targets must be absolute and match all normalized requested targets.
- RED evidence: independent auditor ran `cargo test -p lia-cli --test cleanup_policy_cli`; tests
  compiled and executed, then failed 0/4 because `cleanup_policy` was unknown and legacy behavior
  returned `SHELL_DESTRUCTIVE`. This was the expected RED boundary, not malformed test code.
- Files changed: `crates/lia-gates/src/lib.rs`, `crates/lia-gates/src/shell.rs`, GateConfig literals in
  adapters/bench/CLI tests, `crates/lia-cli/tests/cleanup_policy_cli.rs`, five cleanup fixture folders,
  and this handoff.
- GREEN evidence: independent auditor PASS, 157/157 checks across focused and workspace suites:
  `cargo test -p lia-cli --test cleanup_policy_cli` 4/4; `cargo test -p lia-gates` 26/26;
  shell fixture runner 17/17; `cargo test --workspace` 110/110; M1-only clippy PASS;
  gate-freeze PASS; wire check PASS with two production references; targeted rustfmt and diff checks PASS.
- Production review: no added direct unwrap/expect/panic/todo/unimplemented/unreachable/unsafe; every
  ambiguous/error case denied or propagated; regex construction failure now classifies destructive.
- Off-agent evidence: RED and final GREEN auditor verdicts are transcribed in this section; no durable
  report file was emitted by the auditor.
- Dependencies: none added.
- Known limitation / assurance ceiling: this is deterministic pre-execution path validation at visible
  hook/proxy boundaries, not atomic deletion or protection against same-UID TOCTOU replacement; overall
  assurance remains `GATE`, never CONFINE.
- Non-blocking warnings: `shell.rs` is 944 lines (extract cleanup module later); full-workspace clippy
  has a pre-existing `needless_range_loop` in `tools/lia_wire_check/src/lib.rs:256`, assigned to M6.
- Blocker: none.
- Next action: commit M1, record its hash, then begin M2 RED fixtures.
- Commit: pending

### M2 — production trust wiring

- State: pending
- Requirements: P0-6, P1-10/11/12/14, P2-17, persistent adapter evidence
- Commit: pending

### M3 — telemetry, recovery, performance, lifecycle

- State: pending
- Requirements: P0-2/3/7, P1-20 local portion, P2-1/2/3/4/5
- Commit: pending

### M4 — process contracts and adapter/public-verification fast-follows

- State: pending
- Requirements: P3-5/6/7 local portion, P3-9, live registry client
- Commit: pending

### M5 — confinement, egress, and credential/evidence isolation

- State: pending
- Requirements: P3-4/P3-10 and threat-model isolation promises
- Commit: pending

### M6 — proof and completion audit

- State: pending
- Requirements: every ledger row reconciled; all local acceptance evidence current; external gates exact
- Discovered baseline debt: repair `tools/lia_wire_check/src/lib.rs:256` so full-workspace clippy can
  pass without an allow; re-evaluate extraction of the M1 cleanup classifier from `shell.rs`.
- Commit: pending

## Commit recording convention

Because a commit cannot contain its own hash without history rewriting, each milestone implementation
commit is followed by a documentation-only handoff commit that records the implementation commit hash.
No commit is amended or rewritten. Neither commit includes automated-contributor metadata.
