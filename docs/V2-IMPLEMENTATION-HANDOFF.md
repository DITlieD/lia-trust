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
| L3 | Thin adapters plus capability-derived assurance | Claude, Codex, Gemini CLI, Cursor, and generic boundaries now have explicit mappings and honest per-adapter cells | SHIPPED | adapter conformance and probe-derived report for every shipped adapter | M4 complete; M6 reproof |
| L4 | Ground, syco, AST, taint with production consumers | Claude/Codex writes use central AST dispatch; Codex exposes signed ground/syco/taint paths; unsupported Terminus cells remain CANNOT-OBSERVE | SHIPPED | 8/8 production-path cases plus signed receipts and offline verification | M2 complete; M6 reproof |
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
| P0-6 | durable Harbor journal | Terminus creates a per-trial external journal, verifies each chain, binds receipt to head, rotates by rows/bytes/signed-event age, and recovers only verified bridges | SHIPPED | 4/4 lifecycle CLI cases plus stale-handle, crash-recovery, false-bridge and immutable-archive proofs | M3 complete; M6 reproof |
| P0-7 | per-trial reason telemetry | `deny_by_reason` output histogram | SHIPPED | integration fixture contains stable reason histogram | M3 |
| P1-1 | expanded destructive coverage | destructive pattern pack in `shell.rs` | SHIPPED | hard irreversible regression fixtures remain denied | M1/M6 |
| P1-2 | modern secret patterns | expanded patterns in `secret.rs` | SHIPPED | adversarial secret pack and clean controls | M6 |
| P1-3 | meaningful journal tamper probe | real verifier plus broken-chain fixtures | SHIPPED | event-byte/hash/signature mutation all fail offline | M6 |
| P1-4 | destructive class parity in live arm | frozen trust corpus includes destructive class | SHIPPED | current scorecard class count/catch without pooling lanes | M6 |
| P1-5 | 20-command destructive fixture pack | shell tests/bench fixtures | SHIPPED | all hard fixtures deny and benign controls allow | M1/M6 |
| P1-10 | ground/syco wiring honesty | explicit Codex proxy tools dispatch both gates with receipts; Terminus remains truthfully shell-only | SHIPPED | production denials plus unsupported-adapter CANNOT-OBSERVE cells | M2 complete; M6 reproof |
| P1-11 | AST write admission | central production write dispatch scans supported source types; obsolete helper removed | SHIPPED | Codex write blocks `AST_EVAL`, journals it and verifies separately | M2 complete; M6 reproof |
| P1-12 | taint admission | typed `taint_graph` reaches central dispatch; malformed graphs become signed denials | SHIPPED | malicious and malformed production cases both block with receipts | M2 complete; M6 reproof |
| P1-13 | Claude/Codex measurement | recorded-adapter PREVENT measured; live OAuth agents unmeasured | PARTIAL | current recorded replay; live remains explicit external gate absent credentials | M6 |
| P1-14 | completion admission | Codex `complete_task` blocks `Incomplete`; Claude/generic/Terminus lack completion channels and say CANNOT-OBSERVE | SHIPPED | supported production entrypoint denial plus exact per-adapter cells | M2 complete; M6 reproof |
| P1-20 | utility token tax bound | [MEASURED] TB2 post-fix subset ratio 1.2596608401722553 meets its <1.3 target; historical full-24 ratio remains 2.451; Claw historical ratio 1.7355 misses <1.2 | PARTIAL | reproducible scorecard separates subset/historical data; full post-M3 TB2/Claw reruns remain external/cost-gated | M6 |
| P1-21 | Claw contingency | `claw-utility-contingency.md` | SHIPPED | claims lint and document consistency | M6 |
| P1-22 | policy-approved in-root `rm -rf` | V2 `cleanup_policy` exact-target gate, compiled CLI test, signed journal and offline verifier | SHIPPED | 4/4 cleanup CLI tests, 17/17 shell fixtures, hard-denial regression matrix | M1 complete; M6 reproof |
| P2-1 | bounded external/process timeouts | Terminus subprocess calls are deadline-bounded; generic wrap times out, directly kills/reaps its child, journals exit 124, and fails closed on watcher loss | SHIPPED | timeout and watcher-loss integration 2/2; direct-child scope documented | M3 complete; descendant confinement M5 |
| P2-2 | denial telemetry | cumulative reason, spawn, memo-hit, timeout, latency and memo-size snapshots are emitted structurally per trial | SHIPPED | Python telemetry/memo suite and scorecard parser | M3 complete; M6 reproof |
| P2-3 | lower gate-process overhead | bounded in-memory denial-only memo; allows are never cached | SHIPPED | [MEASURED] local microbenchmark: real gate+verify+head 25.357 ms versus 0.395 microseconds mean memo hit; no Harbor utility claim | M3 complete |
| P2-4 | bounded shareable journal | signed head/tail manifest, pinned-key verifier, full archived DB and signed rotation bridge | SHIPPED | anchor tamper rejection and active/archive verification | M3 complete; M6 reproof |
| P2-5 | duplicate-command memo | TTL/context/capacity-bound verified-denial memo keyed by command and normalized execution context | SHIPPED | duplicate avoids respawn; TTL/context/capacity and never-allow rules proven | M3 complete |
| P2-10 | L6 docs pack | required public documents now present | SHIPPED | claims lint and file checklist | M6 |
| P2-11 | assurance drift prevention | runtime probe executes real boundaries, signed rows, independent generic diff, clean verify and negative tamper; install is UNMEASURED | SHIPPED | 3/3 runtime probes match downward-only truth; defaults are AUDIT/CANNOT-OBSERVE | M2 complete; M6 reproof |
| P2-12 | IS-5 publish path | local action definition, local smoke, and v0.1.0 tag only; no release workflow/prebuilt artifact/sample-repo bundle/different-machine verification evidence | PARTIAL | local prerequisites pass and missing remote/cross-machine proof is either obtained or recorded as an exact external gate | M6 |
| P2-13 | license/advisory checks | `deny.toml`, license policy/scripts | SHIPPED | current dependency audit/license checks | M6 |
| P2-14 | wire coverage | wire map/check/action | SHIPPED | final wire checker | M6 |
| P2-15 | claims separation | `claims.json` separates recorded/live/utility | SHIPPED | claims lint and manual final reconciliation | M6 |
| P2-16 | ground symbol depth | improved symbol matching and fixtures | SHIPPED | positive/negative symbol cases | M6 |
| P2-17 | HL-4 wrapper digest on Terminus tests | Terminus has no per-command result/exit channel; dead helper was removed instead of presenting caller data as wrapper evidence | OBSOLETE-BY-LATER-DESIGN | Terminus test-integrity remains CANNOT-OBSERVE; no fabricated HL-4 path remains | M2 complete |
| P3-1 | second free-model utility lane | local driver exists; actual second-model execution is deferred | PARTIAL | local lane configuration validated; run remains explicitly gated on external model/service availability and cost | M6 |
| P3-2 | Claw companion signal | documented companion metric | SHIPPED | claims remain non-product and non-pooled | M6 |
| P3-3 | AST/taint corpus classes | corpus and runner classes exist | SHIPPED | current by-class replay | M2/M6 |
| P3-4 | network/egress confinement | no backend; capability false | MISSING | supported Linux backend proves egress deny; unsupported hosts fail closed/honest | M5 |
| P3-5 | Gemini CLI and Cursor adapters | documented native hook modules, idempotent installers, installed-wrapper smoke, conformance, signed denials, and honest unmatched-tool behavior `[MEASURED]` | SHIPPED | adapters, installers/launchers, conformance, probes, receipts | M4 complete; live harness agents remain M6 external lane |
| P3-6 | full typed process contract | versioned schema; signed pre-action declaration; typed action/evidence/assumption/claim/outcome state; signed terminal execution manifest | SHIPPED | versioned contract schema, state transitions, validator, CLI/adapter proof | M4 complete; M6 reproof |
| P3-7 | MCP inspection/live agent PREVENT | inspection UX and recorded adapters shipped; live OAuth not run | PARTIAL | inspection conformance; live portion remains exact external credential gate | M4/M6 |
| P3-8 | funding applications | process documentation only by design | EXTERNAL-ONLY | local claims-clean prerequisites; no submission in this task | M6 record |

## Requirement ledger C — V2 / POST-L6 and threat-model promises

| Source | Promise | Current evidence | Status | Exact acceptance evidence | Target |
|---|---|---|---|---|---|
| `docs/shell-rm-policy.md` | explicit policy-approved in-root cleanup | V2 schema and deterministic gate are live with receipt-backed CLI coverage | SHIPPED | M1 independent PASS; final-head replay in M6 | M1 complete; M6 reproof |
| roadmap P3-1 | second utility model lane | lane machinery exists, execution deferred | PARTIAL | validate local configuration; record external model/service/cost execution gate | M6 |
| roadmap P3-4 | network/egress CONFINE | capability key false, no backend | MISSING | local Linux network namespace/deny proof where supported | M5 |
| roadmap P3-5 | Gemini CLI adapter | documented BeforeTool mapping, install merge, conformance and installed-wrapper signed deny | SHIPPED-LOCAL | real supported hook/proxy entrypoint plus signed deny | M4 complete |
| roadmap P3-5 | Cursor adapter | fail-closed shell/MCP hook mapping, install merge, conformance and installed-wrapper signed deny | SHIPPED-LOCAL | real supported hook/proxy entrypoint plus signed deny | M4 complete |
| roadmap P3-6 | full typed process-contract validator | pre-action contract digest and full execution-state terminal manifest are enforced | SHIPPED | schema, transition validator, reason codes, CLI/adapter proof | M4 complete |
| roadmap P3-7 | live Claude/Codex agent PREVENT | recorded lanes only | PARTIAL | local conformance complete; live run requires owner OAuth/service | M6 |
| roadmap P3-8 | funding applications | docs only, intentionally post-release | EXTERNAL-ONLY | no external submission; claims-clean template/state only | M6 |
| roadmap P3-9 / HL-5 | optional cosign public-log verification | digest-pinned external cosign path with identity/issuer pins, input hashes, bounded process-group/output lifecycle | SHIPPED-LOCAL | optional executable verifier with timeout and fixture/mock; live log external | M4 complete; live log M6 external gate |
| roadmap P3-10 | Linux namespace CONFINE backend | absent | MISSING | supported-host namespace/process proof and honest fallback | M5 |
| threat model | signing identity outside agent principal | key file shares user identity today | PARTIAL | brokered FD/process boundary and file-permission checks; OS principal separation external | M5 |
| threat model | credential broker | capability false, env allowlist still includes credential-adjacent vars | MISSING | secret-minimized child environment and scoped credential delivery/expiry | M5 |
| threat model | live registry dependency evidence | fixed official crates.io/npm HTTPS origins, pinned client, bounded response/process, externally pinned and age-bounded offline cache | SHIPPED-LOCAL | bounded client, pinned response evidence, offline/cache semantics, timeout | M4 complete; live network sample M6 optional |
| threat model | persistent evidence outside writable worktree | generic wrap signs process/diff events externally; Terminus uses per-trial external evidence; hook install still shares user identity | PARTIAL | M2 persistence/tamper proof complete; separate-principal ownership remains | M5 |

## Discrepancy map

| Claim/design record | Live behavior | Resolution |
|---|---|---|
| P1-22 `DONE-DOC` can look complete | no context-dependent recursive delete exists | reclassify as DOC-ONLY and implement in M1 |
| “41/41 done” includes documentation-only deferrals | six security/product behaviors remain absent or partial | preserve historical score but use this implementation ledger for V2 |
| L4 components exist | existence/CLI reachability is broader than normal adapter enforcement | wire supported production paths or lower capability claims in M2 |
| Terminus has a durable-journal option | default fallback can be temporary and error paths fail open | make lifecycle explicit and fail closed in M2/M3 |
| Generic wrap reports a journal path and its probe asserts immutable/offline evidence | M2 writes signed attempted/observed/diff rows outside the worktree and verifies clean/tampered copies | resolved locally; lifecycle/rotation continues in M3 |
| Claude install probe asserts shell-result capture and completion gate | install is now UNMEASURED; runtime probe keeps both cells CANNOT-OBSERVE | resolved; a future observing boundary must earn any stronger cell |
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

- State: `MILESTONE_COMMITTED`
- Timestamp: `2026-07-22T04:02:39+09:00`
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
- Next action: begin M2 RED fixtures for production-path journal/AST/taint/test/completion evidence.
- Commit: `e18c624e31858cb22be9d24f6b6532acb66e8d8e`

### M2 — production trust wiring

- State: `MILESTONE_COMMITTED`
- Timestamp: `2026-07-22T04:55:05+09:00`
- Starting HEAD: `fd664e1e34e9cf2821b1f08ee5d76ca7a5ded366`
- Requirements: P0-6, P1-10/11/12/14, P2-17, persistent adapter evidence
- RED evidence: independent auditor compiled and ran
  `cargo test -p lia-cli --test production_trust_paths`; 0/7 tests passed as expected. Each test
  independently reached the production CLI/adapter boundary and exposed one missing behavior:
  generic wrap emitted no journal; Codex write admitted AST `eval`; a separate Codex write admitted
  a valid untrusted-to-destructive taint graph; `ground_claim` and `check_agreement` were unknown
  proxy tools; `EVIDENCE_INCOMPLETE` returned `allowed:true`; and probe-supplied per-gate cells were
  ignored. `rustfmt --check` passed and the auditor found no malformed fixture or setup failure.
- Completed behavior: generic wrap signs attempted/observed/final-diff events outside the child
  worktree; central adapter dispatch emits signed AST/taint/ground/syco outcomes; `Incomplete` and
  `Unsupported` block; Codex exposes explicit grounding/agreement tools and survives malformed framed
  calls with a signed `ADAPTER_INVALID_INPUT`; install output is UNMEASURED; runtime assurance probes
  earn each cell through production denials/diff evidence, clean chain verification and negative
  tamper checks. Terminus now uses an external per-trial journal, random per-instance signing secret,
  bounded gate/verifier timeouts, deny-only memoization, fail-closed protocol handling, clean offline
  verification and exact returned-receipt/journal-head binding.
- Architectural decisions: caller-supplied Codex `run_test` data is not wrapper evidence, so Codex
  test-integrity remains CANNOT-OBSERVE. Claude PreToolUse cannot see test results, completion or
  dependency operations. Terminus cannot see per-command exit status, so the dead HL-4/completion
  helpers were removed and those cells remain CANNOT-OBSERVE instead of fabricating evidence.
- Files changed: `Cargo.lock`; `lia-gates` payload schema; `lia-adapters` Cargo/dispatch/Codex/generic/
  assurance/install/conformance/inspection surfaces; CLI MCP boundary and install smoke;
  `production_trust_paths.rs`; `bench/harbor/lia_decision.py`, Terminus integration and seven unit
  cases; assurance truth/probe/docs; this handoff.
- Dependencies: internal workspace dependencies `lia-ground` and `lia-syco` added to `lia-adapters`;
  no new external package.
- Current assurance ceiling: `GATE` only for explicitly observed hook/proxy gates. Claude test and
  completion cells, Codex test-integrity, and generic test/completion/shell/dependency/secret cells
  are CANNOT-OBSERVE; generic filesystem remains DETECT. No adapter claims CONFINE.
- GREEN evidence: final independent audit PASS. `cargo test --workspace --no-fail-fast` passed
  117/117; production trust paths 8/8; `lia-adapters` 18/18; Terminus decision tests 7/7; install
  smoke 1/1; runtime assurance probes 3/3. `cargo check --workspace`, targeted rustfmt,
  `git diff --check`, gate freeze and wire checks all passed. Claude produced three real denials and
  five signed rows; Codex five denials and seven rows; generic a real `touched.txt`, independently
  matching diff digest and three rows. Every clean chain verified and every mutated copy failed.
- Production review: no new direct panic/expect/unwrap/todo/unimplemented/unreachable/unsafe in
  production. Invalid quality payloads become signed denial outcomes and a malformed MCP call does
  not terminate the following frame. Obsolete unit-only AST/taint helpers were removed so wire check
  proves the central production consumer.
- Off-agent evidence: RED, intermediate BLOCK and final PASS verdicts from `m2_auditor`, plus the
  Terminus fail-closed PASS from `terminus_red_auditor`, are transcribed here; no separate report file
  was emitted.
- Retained limitations: probe JSON remains operator-supplied and unsigned, so reports are operational
  summaries rather than attestations; a live Harbor/Terminus run was not available. The unchanged
  contract parser contains one pre-existing panic. There is still no complete mediation, native Codex
  tool interception, network confinement, credential broker or separate OS principal.
- Next action: commit M2, record its hash, then begin M3 with RED lifecycle/timeout/cache/telemetry
  fixtures. Rotation, cleanup and stale-resource recovery remain M3 work.
- Blocker: none.
- Commit: `f054ddd6d4b4b2c255d8278243dd1ea02a5dc32e`

### M3 — telemetry, recovery, performance, lifecycle

- State: `MILESTONE_COMMITTED`
- Timestamp: `2026-07-22T06:30:38+09:00`
- Starting HEAD: `3771ca7b82fd11560278d4e4586d45da0e50ff10`
- Requirements: P0-2/3/7, P1-20 local portion, P2-1/2/3/4/5
- RED evidence: the independent auditor first proved that the planned boundaries did not exist:
  `DenyMemo`/`GateMetrics`, wrap timeout and journal lifecycle CLI commands were absent. Later
  adversarial source review independently found and blocked unsigned-age rotation, dropped watcher
  errors, incomplete child cleanup, crash windows, unpinned anchors, overflow, missing fsyncs,
  concurrent append/rotation races, long-lived SQLite handles spanning rename, and immutable-WAL
  sidecar bypasses. Each BLOCK was resolved before this milestone was accepted.
- Completed behavior: Terminus now uses a TTL/context/capacity-bound memo for independently verified
  denials only (allows are never cached), bounded gate/verifier processes, reason/spawn/hit/timeout/
  latency/memo-size telemetry, and automatic journal maintenance. Generic wrap owns a deadline,
  kills and reaps the direct child, records stable timeout/observation-failure reasons and never
  releases a child that may still be live. Cleanup diagnostics are count+first+last bounded.
- Journal architecture: journal handles retain paths, not SQLite connections. Every live read/write
  opens an ephemeral connection under a cross-process lifecycle lock; rotation holds that lock over
  recovery, checkpoint, durable signed state, both renames, directory fsyncs and final validation.
  Pre-rotation handles therefore follow the new active path. Recovery promotes only a signed bridge
  whose canonical archive, row count and prior head all verify. A false/orphan bridge never creates
  a fresh genesis journal. Replacement lock artifacts are removed in normal, stale and recovery
  paths.
- Share/offline behavior: rotation preserves the complete old database and begins the new active
  journal with a signed bridge. Signed head/tail manifests require an operator-pinned Ed25519 public
  key and authenticate retained hashes without claiming to prove the omitted middle. Normal reads
  join the lifecycle lock. Explicit `journal-verify --immutable` is only for stable offline copies;
  it canonicalizes the target, preserves native path bytes, refuses WAL/SHM/rollback entries or
  metadata errors, and uses SQLite immutable read-only mode without adjacent lock state.
- RED-to-GREEN evidence: focused lifecycle audit passed 6/6 after the path-only refactor; journal CLI
  integration passed 4/4; wrap lifecycle passed 2/2; missing-open, cross-connection serialization,
  stale-handle and immutable canonical-sidecar cases all passed. The final security source review
  returned PASS with no remaining crash, lock-order, stale-inode, recovery or immutable-sidecar
  BLOCK.
- Full independent audit [MEASURED]: Python Harbor tests 11/11. Rust workspace 129/129 distinct tests and 140
  executions passed; `cargo check --workspace`, scoped strict clippy for journal/adapters/CLI,
  gate-freeze, wire-check, targeted rustfmt, six-file Python compilation, changed/new JSON parsing
  and `git diff --check` all passed. After claims-lint was found traversing ignored `.venv`, datasets,
  runs and internal session files, its boundary was made explicit without excluding public docs or
  `bench/harbor/results`; claims unit tests passed 3/3 and repository-root claims-lint finished clean.
- Performance evidence [MEASURED]: `bench/harbor/results/m3-deny-memo-measure.json` records one local run where a
  real gate plus journal verification and receipt-head validation took 25.357 ms and 10,000 verified
  denial memo hits averaged 0.395 microseconds, an observed 64133.903x ratio [MEASURED]. This is
  `LOCAL_MICROBENCHMARK_NOT_HARBOR_UTILITY`, not a daemon claim and not a TB2/Claw rerun.
- Utility honesty [MEASURED]: the scorecard now consumes an explicit historical full-24 TB2 artifact and the
  post-fix subset separately. TB2 subset token ratio 1.2596608401722553 meets its <1.3 local target;
  the historical full-24 ratio is ~2.451. Claw remains historical at ~1.7355, above <1.2. No full
  post-M3 Harbor utility run occurred; gate telemetry fields say `NOT_REMEASURED_AFTER_M3` when no
  current trajectory snapshot exists.
- Files changed: journal/CLI/generic/Claude adapter sources and lifecycle integrations; Terminus
  decision/telemetry/publisher code and tests; reproducibility/measurement artifacts; README,
  claims and historical analysis labels; claims-lint traversal/false-positive boundaries; this
  handoff.
- Dependencies: none added.
- Assurance ceiling and retained limits: `GATE`, not CONFINE. Generic cleanup owns only the direct
  wrapped child, not descendant process groups or egress. A persistent kernel refusal to kill/reap
  deliberately exceeds the nominal deadline in fail-stop mode rather than returning with a live
  child. The local memo result is one machine microbenchmark. Full Harbor utility and live gate
  telemetry remain unmeasured after M3. Signed state protects cooperative continuity within the
  same-UID threat model; separate-principal evidence/key ownership belongs to M5.
- Off-agent evidence [MEASURED]: successive `m2_auditor`, `m1_auditor`, and `terminus_red_auditor` RED/BLOCK/
  GREEN verdicts are transcribed here. The final long auditor turn hit the account subagent usage
  ceiling only after returning all command results and identifying the claims-lint BLOCK; the
  independent `m1_auditor` then verified the fix with 4/4 audit tiers PASS.
- Blocker: none.
- Next action: begin M4 RED contracts/adapter/public-verification fixtures from current official
  interface evidence.
- Commit: `01b957b12f858ac128dc1c6dd316f772c7c5fdde`

### M4 — process contracts and adapter/public-verification fast-follows

- State: `AUDITED_READY_TO_COMMIT`
- Requirements: P3-5/6/7 local portion, P3-9, live registry client
- Official interface grounding: Gemini `BeforeTool` fields/decision/exit behavior from
  `https://geminicli.com/docs/hooks/reference/`; Cursor hook events, permission response, and
  security-critical `failClosed` flag from `https://cursor.com/docs/hooks`; cosign `verify-blob`
  bundle plus certificate identity/issuer pins from
  `https://docs.sigstore.dev/cosign/verifying/verify/`; authoritative crates sparse-index and npm
  registry semantics from `https://doc.rust-lang.org/cargo/reference/registry-index.html` and
  `https://docs.npmjs.com/cli/v8/using-npm/registry/`.
- RED evidence: independent auditor compiled and ran
  `cargo test -p lia-cli --test m4_process_adapters_public_registry`; 0/4 cases passed because the
  process validator, Gemini/Cursor hook entrypoints, public verifier, and registry evidence command
  did not exist. This was valid missing-behavior RED, not fixture failure.
- Completed process boundary: `lia-process-contract-v1` declares objective, assumptions, required
  evidence, allowed actions, completion predicate, and honest-stop conditions. A signed
  `process_contract_declared` digest must precede every referenced action. Evidence requirement,
  execution reference, and signed `EvidenceCaptured.kind`/digest must agree. Complete/honest-stop
  receipts bind a deterministic execution manifest containing contract digest, action/evidence
  receipts, assumption support, unresolved claims, and terminal assertion. Honest stop also binds
  the declared condition and typed non-empty tried/missing/route data. Generic wrap emits and
  validates this contract without claiming to be a planner or repair system.
- Completed adapters: Gemini CLI documented `BeforeTool` mapping for shell/write/replace/read with
  additive-field compatibility and deny on an unsupported tool that reaches the matcher; Cursor
  documented shell/MCP hooks with `failClosed:true`, mapped shared-gate dispatch, and explicit `ask`
  for unknown MCP semantics. Install/status/uninstall merge all four harness homes idempotently;
  fixture-installed Gemini/Cursor wrappers produce signed hard denials and the combined journal
  verifies.
- Completed external evidence: `public-verify` delegates to a digest-pinned `cosign`, pins identity
  and issuer, records verifier/artifact/bundle hashes and sizes, detects input changes, caps output,
  and on Unix owns a process group plus deadline-bounded drains. `registry-evidence` rejects custom
  origins and redirects, requires HTTPS/TLS and a pinned client, caps response/output/time, parses
  official crates.io/npm shapes, and only accepts offline cache with external response+metadata pins
  and a maximum age. Cached positives use distinct `*_PINNED_CACHE` reasons.
- Adversarial audit history: first GREEN checkpoint passed 12/12 `[MEASURED]`, then expanded focused/adapters/
  conformance checks passed 33/33 `[MEASURED]` but independent source review returned BLOCK because evidence kinds,
  assumption/claim state and completion receipts were not manifest-bound and arbitrary helper
  binaries could mint VERIFIED. Remediation added the signed execution manifest, evidence-kind and
  ordering checks, executable/source/cache trust pins, input hashes, and process-group lifecycle.
  Re-audit passed 33/33 `[MEASURED]` with no BLOCK; a remaining inherited-pipe warning was then closed with
  deadline-bounded channels and leader-exits/descendant-holds-pipe tests. Final focused audit passed
  4/4 `[MEASURED]` with no warning or block.
- Final audit `[MEASURED]`: `cargo test --workspace` passed 135/135 `[MEASURED]` and
  `cargo check --workspace` passed. Conformance passed 10/10 `[MEASURED]`; gate freeze, the wire
  checker over every changed/new Rust file, docs/README claims lint, JSON parsing, and
  `git diff --check` all passed. Installed-wrapper smoke passed 1/1 `[MEASURED]`. All 18/18
  changed/new Rust files were formatting-clean `[MEASURED]`.
- Baseline debt `[MEASURED]`: strict clippy still reports three findings in unchanged `lia-gates`
  code (two `needless_return`, one `too_many_arguments`), and workspace rustfmt reports drift in
  18 unchanged files. Independent audit found no M4-delta lint/format defect and no BLOCK. These
  baseline findings are assigned to M6 rather than concealed as an M4 pass.
- Local measurement honesty: all cosign/client, Gemini/Cursor, and cache results in this milestone are
  local fixtures/conformance. No live Gemini/Cursor cloud-agent session, Sigstore public-log lookup,
  or real registry network lookup is claimed. Gemini consumer-tier migration affects availability,
  not the pinned adapter schema.
- Dependencies: direct `libc` use for Unix process-group termination (already present transitively,
  now explicit in the relevant crates); `sha2` test dependency for deterministic fixture pins.
- Assurance ceiling: mapped hook/MCP paths are `GATE` `[MEASURED]`; unmatched/non-tool behavior, same-UID signer or
  executable replacement, dynamic-library trust, and network/process CONFINE remain outside this
  milestone. Operator-supplied executable/cache digests are trust roots and must live outside agent
  write roots. Windows lacks the Unix process-group guarantee and must not inherit that claim.
- Blocker: none for local M4 scope. Live agent/public-log/registry-network evidence remains optional
  external M6 proof and is never substituted by fixture results.
- Next action: commit the audited M4 implementation, record its hash, then begin M5 RED
  confinement/egress/credential isolation fixtures.
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
