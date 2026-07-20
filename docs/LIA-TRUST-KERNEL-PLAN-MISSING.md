# LIA Trust Kernel — what is still missing vs `LIA-TRUST-KERNEL-PLAN.md`

**Plan source:** `/home/lied/teikoku/elai/workflow/reasoning/LIA-TRUST-KERNEL-PLAN.md`  
**Codebase:** `/home/lied/teikoku/lia-trust`  
**Generated:** 2026-07-20  
**Last flip:** 2026-07-20 (Kernel install + Claude/Codex PREVENT + L6 pack)

This file is a **gap inventory only**: items the plan requires (or marks as post-L6 but still “missing for full plan completion”) that are **not fully delivered** in the current tree.  
It does **not** re-list closed ELAI-private surface (planning, GRC, multi-agent recovery, etc.) — those are correctly **out of scope** for this repo.

**Legend**

| Tag | Meaning |
|-----|---------|
| **MISSING** | Plan requires it for v1 / unit L0–L6; not present or not production-wired |
| **PARTIAL** | Exists in some form; fails plan DONE criteria (probe-derived, multi-harness, full field, etc.) |
| **CLOSED** | Delivered with evidence pointer this cycle |
| **POST-L6 (plan)** | Plan explicitly defers after L6; still “missing” relative to full plan surface |
| **OPS / PUBLISH** | Engineering exists but release / third-party path incomplete |

---

## 0. Executive gap summary

| Bucket | Count (approx.) | Notes |
|--------|-----------------|--------|
| Core open surface (gates/journal/ground/syco/ast/taint/adapters) | **Shipped** | Seven gates, journal+Ed25519, ground/syco, AST/taint min, thin adapters |
| **Kernel install** (Claude Code + Codex) | **CLOSED** | `lia install` / `status` / `uninstall`; fixture smoke + HARD path |
| Plan **unit L0–L4** production quality | **Partial** | Smokes exist; IS-2 hook HARD green; live agent optional |
| Plan **L5 headline** (3 harness PREVENT OFF/ON) | **CLOSED (adapter paths)** | Claude Code + Codex + generic: recorded-adapter MEASURED; live-agent MEASURED on free bridge for claude-code + codex |
| Plan **L6 release-readiness pack** | **CLOSED (local pack)** | threat model, SECURITY, COC, CONTRIBUTING, harness table, guarantee matrix, CONTRACTS, quickstart; local release binary; no public GitHub tag in this env |
| Plan **L7 funding apps** | **MISSING** (correctly post-release) | `programs.md` is a placeholder |
| Strategy / plan **post-L6 fast-follows** | **MISSING by design** | Process-contract full type, Gemini/Cursor, Linux CONFINE backend, cosign path |

**Bottom line:** Kernel TCB + **one-command install** + **Claude/Codex PREVENT** + **L6 docs pack** are delivered. Remaining work is POST-L6 polish, public tag/publish, and ELAI-closed surfaces.

---

## 1. Hard lessons (HL-*) — residual gaps

| HL | Plan requirement | Status |
|----|------------------|--------|
| HL-1 | Ed25519 over gate-manifest + identity; Merkle is integrity not auth | **Met** for receipts |
| HL-1 | Explicit **Merkle root** as integrity primitive (not only sequential blake3 chain) | **PARTIAL / POST-L6** — sequential `prev_hash`/`row_hash` chain, not a Merkle tree API |
| HL-2 | Assurance **probe-derived at runtime**, never hard-coded overclaim | **PARTIAL** — `assurance_truth.json` + `from_probe`; install emits default probe notes |
| HL-2 | Generic wrap **never claims complete mediation** | **Met**; install status prints GATE not CONFINE |
| HL-3 | Honesty matrix: cloud = trace-authenticated not byte-replay | **PARTIAL** — cassette/live separation in claims |
| HL-4 | Full wrapper field set on test-integrity | **Met** in gate schema |
| HL-5 | Optional **cosign verify-blob** shell-out for public-log path | **POST-L6 / MISSING** |
| HL-6 | claims-lint over marketing docs | **Met** for `docs/` after false-positive word-boundary fix |

---

## 2. Architecture layout vs plan §3

| Plan artifact | Status |
|---------------|--------|
| All listed crates present | **Met** |
| Bridge scripts under **bun** (never node) | **POST-L6 / MISSING** — no bun bridge package; Python Harbor agents only |
| `CONTRACTS.md` with pinned Claude/Codex field names | **CLOSED** — `docs/CONTRACTS.md` + `contracts.json` install pins |
| Size-ceiling manifest for verifier binary (Q-8 doctrine) | **MISSING** — no enforced size gate |
| Installable Kernel entry (`lia install`) | **CLOSED** — `crates/lia-adapters/src/install.rs` + CLI |

---

## 3. Seven core gates — residual gaps (plan §4 / L2)

All **seven gate IDs ship**. Residual incompleteness is **PARTIAL** depth (live registry, full shell AST, universal path coverage) — see historical notes; landmine fixtures still grow. **Not** blocking Kernel install.

---

## 4–5. Owner coverage / strategy ladder

Unchanged residual: syco depth PARTIAL; CONFINE never for v1; Gemini/Cursor **POST-L6**.

---

## 6–8. Units L0–L2

Core **Met**. IS-1 remains PARTIAL as continuous published proof (script exists).

---

## 9. Unit L3 / IS-2 — residual missing

| Plan deliverable | Status |
|------------------|--------|
| Claude Code PreToolUse bridge | **CLOSED** — hook + install wiring + IS-2 smoke + install-path HARD |
| Codex/MCP proxy | **CLOSED** — proxy + install + live/recorded PREVENT |
| Generic wrap worktree + honesty | **PARTIAL** — present; not CONFINE |
| `bench/probe_assurance.sh` | **PARTIAL** — script + truth table |
| `CONTRACTS.md` settled | **CLOSED** |
| IS-2 real HARD via **hook path** | **CLOSED** — `tools/scripts/is2_smoke.sh` + `install_kernel_smoke.sh` |

Evidence: `tools/scripts/is2_smoke.sh`, `tools/scripts/install_kernel_smoke.sh`, scratch `is2-hook-enforce.log` / `codex-enforce.log`.

---

## 10. Unit L4 / IS-3

Library-level **Met**; plan-grade per-language fixture matrix still **PARTIAL**.

---

## 11. Unit L5 / IS-4 — residual missing (headline number)

| Plan deliverable | Status |
|------------------|--------|
| Frozen adversarial corpus | **Met** |
| **Three PREVENT model lanes** OFF/ON: Claude Code, Codex, generic+Devin-bridge | **CLOSED** for adapter PREVENT |
| Claude Code PREVENT recorded-adapter OFF/ON | **CLOSED [MEASURED]** → `bench/results/claude-code-prevent-recorded.json` |
| Codex PREVENT recorded-adapter OFF/ON | **CLOSED [MEASURED]** → `bench/results/codex-prevent-recorded.json` |
| Claude Code PREVENT live-agent (free bridge) | **CLOSED [MEASURED]** → `bench/results/claude-code-prevent-live-swe-1-6.json` |
| Codex PREVENT live-agent (free bridge) | **CLOSED [MEASURED]** → `bench/results/codex-prevent-live-swe-1-6.json` |
| Recorded vs live never pooled | **Met** in claims doctrine |
| Optional Devin **cloud agent** DETECT-only post-hoc lane | **MISSING** |
| Full TB2-24 / Claw-80 as product proof | Companion only (prior MEASURED) |

---

## 12. Unit L6 — release / publish pack

| Plan deliverable | Status |
|------------------|--------|
| Conformance suite | **Met** |
| `lia verify-run` AUDIT mode | **Met** |
| README five-minute quickstart (install cmd) | **CLOSED** — `docs/README.md` |
| Assurance matrix | **PARTIAL** — `docs/assurance.md` + truth JSON |
| ELAI/LIA upsell mechanical from CANNOT-OBSERVE | **CLOSED** enough — `docs/upsell.md` + `docs/guarantee-matrix.md` |
| Threat-model doc | **CLOSED** — `docs/threat-model.md` |
| Guarantee / non-guarantee matrix | **CLOSED** — `docs/guarantee-matrix.md` |
| SECURITY.md | **CLOSED** |
| CONTRIBUTING.md | **CLOSED** |
| CODE_OF_CONDUCT.md | **CLOSED** |
| Harness compatibility table | **CLOSED** — `docs/harness-compatibility.md` |
| **Tagged release** with prebuilt `lia` binaries | **OPS** — local `cargo build -p lia-cli --release` artifact; public tag not pushed from this env |
| Explicit useful-without-commercial-harness README | **CLOSED** |
| Apache-2.0 + cargo deny | **Met** |
| IS-5 third-party clone on different machine | **PARTIAL** — local-IS-5 smoke only |

---

## 13. Unit L7 — funding applications

| Plan deliverable | Status |
|------------------|--------|
| Wait after public maintained tag, then apply | **MISSING** (correct order) |
| `docs/programs.md` rows | **MISSING** content (placeholder) |

---

## 14–16. Isolation / protocol / adapter honesty

Unchanged POST-L6 residuals: namespaces CONFINE, credential broker, network PREVENT, Gemini/Cursor, full process supervisor (ELAI).

**Claude Code / Codex path coverage:** install wires hook + MCP; PREVENT MEASURED on both recorded-adapter and live-agent (free bridge). Still not complete mediation.

---

## 17. Integration smokes (IS-1 … IS-5)

| Smoke | Current state |
|-------|----------------|
| IS-1 | Script exists; PARTIAL continuous published proof |
| IS-2 | **CLOSED** green (`is2_smoke.sh`) |
| IS-3 | PARTIAL via corpus/live loop |
| IS-4 | **CLOSED** multi-harness PREVENT local |
| IS-5 | Local smoke PARTIAL; cross-machine missing |

---

## 18. What is **not** “missing” (scope control)

Do **not** treat these as LIA Trust Kernel gaps — plan §0 closes them:

- Claim extraction, claim-risk scoring, evidence planning  
- Planning FSM, decomposition, recovery, multi-agent orchestration  
- DKG / RAG / repo maps / context allocation  
- Auto-repair after gate fail  
- Full sandbox orchestration product  
- Reviewer cockpit / commercial control plane  
- Self-improvement (DGM) loop  
- Commercial Harness / Canvas UI (marketing image brand layers)

---

## 19. Suggested priority order (remaining)

1. Public tagged release + binary artifacts (OPS).  
2. IS-5 true cross-machine recompute.  
3. HL-5 cosign optional path + verifier size ceiling.  
4. Probe-derived assurance refresh on every publish.  
5. **POST-L6** — process-contract types, Gemini/Cursor, namespaces CONFINE, live registries.

---

## 20. Related files

| File | Role |
|------|------|
| Plan | `elai/workflow/reasoning/LIA-TRUST-KERNEL-PLAN.md` |
| Install kernel | `crates/lia-adapters/src/install.rs`, `lia install` |
| Contracts | `docs/CONTRACTS.md`, `crates/lia-adapters/contracts.json` |
| PREVENT results | `bench/results/*prevent*.json` |
| Install smoke | `tools/scripts/install_kernel_smoke.sh` |
| This gap list | `docs/LIA-TRUST-KERNEL-PLAN-MISSING.md` |

---

*End of gap inventory. Update this file when a plan unit’s VERIFY / IS-N / L6 checklist item flips green with off-agent evidence.*
