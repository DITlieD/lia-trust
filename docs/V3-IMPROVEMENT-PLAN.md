# LIA Trust Kernel — V3 improvement plan

**Status:** draft plan (not started)  
**SemVer target:** `0.3.0` (pre-1.0; V3 = feature milestone, not SemVer major)  
**Baseline:** `v0.2.2` on `main` (V2 feature complete M0–M6 + Grok envelope fix + install home scope)  
**Authority:** this document; implement via a future `docs/V3-IMPLEMENTATION-HANDOFF.md`  
**Date opened:** 2026-07-24  

---

## 1. Why V3

V2 closed the local trust-boundary product: seven gates, adapters, process contracts,
optional Linux confine, honest assurance cells, public install path.

**0.2.1 / 0.2.2** fixed real production pain when Grok Build reuses Claude hooks:

| Incident class | Root cause | Fix |
|----------------|------------|-----|
| False deny storm on matched tools | camelCase envelope / Grok tool names fail-closed at parse | Adapter aliases + tool map (`v0.2.1`) |
| False deny on home paths | install defaulted `allowed_roots` to clone cwd | Default `$HOME` + preserve prior roots (`v0.2.2`) |

What remains is not “more gates for the same Claude shell.” It is **multi-harness
mediation depth**, **agent-tree visibility**, and **install/ops livability** so the
kernel stays useful when operators run parent agents, subagents, MCP, and mixed
coding harnesses day to day.

V3 makes LIA **correct and legible across the modern agent surface** without claiming
complete mediation or commercial harness features (planning, auto-repair, claim extraction).

---

## 2. North star

> **Every tool invocation the harness can show LIA is either gated with a signed
> receipt, or honestly labeled CANNOT-OBSERVE — including child agents — and
> install never reintroduces a false-deny configuration.**

Success looks like:

1. Grok / Claude / Codex / Cursor / Gemini share one **envelope + tool-name contract**
   with fixtures, not one-off shell wrappers.
2. **Spawn and child-tool** paths have an explicit mediation story (GATE or
   CANNOT-OBSERVE with parent/child linkage where the harness exposes events).
3. **Matcher coverage** matches real operator tools (shell, FS, MCP, spawn) without
   fail-open holes that look like “security.”
4. **Install / status / doctor** prevent the class of root-scope and hook-compat
   bugs that produced 0.2.x false denials.
5. Assurance reports and claims remain **downward-only** and probe-derived.

Non-success: pretending subagents are mediated when the harness never fires a hook;
raising CONFINE claims for hook adapters; pooling live/recorded metrics.

---

## 3. Principles (frozen for V3)

1. **GATE where hooks fire; never invent observation.** If the harness has no event,
   the cell is CANNOT-OBSERVE — not silent allow marketed as protect.
2. **Fail-closed on eval/parse errors; fail-open only for tools with no gate map** —
   and the allow reason must be explicit (`no gate mapped for tool`). Prefer mapping
   over weakening fail-closed.
3. **Translate before deny.** Multi-harness envelopes (snake_case / camelCase / tool
   aliases) are adapter work, not operator work.
4. **Install is a trust decision.** Defaults must match how people use agents
   (`$HOME` or explicit multi-root), and reinstall must not silently shrink scope.
5. **Child agents inherit honesty.** Parent spawn can be gated; child tools are gated
   only if child PreToolUse (or equivalent) runs LIA; journals may link parent/child
   when session ids exist.
6. **No commercial fill in Kernel.** Auto-repair, free-text claim extraction, and
   full multi-agent *recovery* stay Harness/Canvas (see `docs/upsell.md`).
7. **Ship as `0.3.0`.** V3 is a feature milestone under pre-1.0 SemVer.

---

## 4. Non-goals (V3)

- Complete mediation / process supervisor replacing hooks
- Cross-platform CONFINE backends (Windows/macOS) beyond research notes
- Live OAuth Claude/Codex Harbor measurement as a release gate (remain external lanes)
- Funding applications (P3-8) and commercial Canvas work
- Second free-model utility lane cost runs (P3-1) as a hard gate
- Changing V1/V2 gate *meaning* (destructive still hard-deny; cleanup still
  policy-bounded)

---

## 5. Lessons locked in from V2 + 0.2.x

Carry these into V3 design reviews:

| Lesson | V3 implication |
|--------|----------------|
| Claude-native schema ≠ Grok wire format | First-class multi-envelope parse in every hook adapter; golden fixtures per harness |
| Matcher coverage ≠ tool inventory | Document and test **what is matched**; expand matchers deliberately |
| `spawn_subagent` / Task often unmatched | Explicit spawn policy story; do not confuse “parent blocked” with “child untrusted” |
| Install from clone cwd shrinks world | Doctor + status must show roots; default home; preserve prior config |
| Plugin translators vs global Claude path | Prefer **kernel adapter** fixes over depending on third-party wrapper scripts |
| Fail-closed parse errors look like policy denials | Distinct stderr / reason codes: `ADAPTER_PARSE` vs `FS_OUT_OF_SCOPE` vs `SHELL_*` |
| Subagent full visibility already listed as non-guarantee | V3 can **improve** partial visibility; must not claim full tree without harness events |

---

## 6. Workstreams

### W1 — Multi-harness envelope & tool contract (foundation)

**Problem:** Each harness invents tool names and JSON shapes; LIA’s Claude adapter
was the only production path Grok hit via compat hooks.

**Deliverables:**

- Shared `EnvelopeNormalize` module used by `claude-code`, optional `grok` adapter,
  and install wrappers.
- Canonical tool map table (checked into `contracts.json` or `docs/harness-compatibility.md`):

  | Wire / harness name | Gate tool | Payload fields |
  |---------------------|-----------|----------------|
  | Bash, run_terminal_command, shell | Bash | command |
  | Read, read_file | Read | file_path \| target_file \| path |
  | Write, write | Write | path + content aliases |
  | Edit, search_replace, StrReplace | Edit | path + old/new or content |
  | Delete, delete_file | Delete | path |
  | Task, spawn_subagent | (spawn policy) | prompt, agent_type, … |
  | MCP `server__tool` | per-server policy or inspect-only | … |

- Golden fixtures: Claude snake_case, Grok camelCase, Cursor shell/MCP, Gemini BeforeTool.
- Conformance cases that **must** allow in-scope and deny OOS for each envelope.
- Reason code `ADAPTER_PARSE` (or existing Invalid path) distinct in journal when possible.

**Exit:** No harness-specific Python normalizer required for correctness; wrappers stay thin.

### W2 — Mediation coverage & matcher honesty

**Problem:** Tools outside the PreToolUse matcher (grep, list_dir, many MCP calls,
spawn) never see LIA — operators read that as “bypass.”

**Deliverables:**

- `lia status` / `lia doctor` print **mediated tool set** vs **known unmediated** for
  each installed harness.
- Optional expanded Claude/Grok matcher profiles:
  - `default` — current destructive/write/shell/read set
  - `broad` — includes Task/spawn, optional Glob/Grep as Read-scope-only
  - `strict-mcp` — experimental MCP name patterns (fail-closed unknown MCP mutate)
- Policy knobs: `mediate_spawn`, `mediate_mcp_mutations`, `read_tools_as_fs_scope`.
- Docs: harness table updated with Grok row + matcher profiles.

**Exit:** Operator can answer “what does LIA see in this install?” in one command.

### W3 — Agent-tree / subagent visibility (core V3 product)

**Problem:** Guarantee matrix: *Subagent full visibility → Partial keys only*.
Parent false-denies and child shells confused operators; spawn is usually unmediated.

**Design (phased):**

| Phase | Name | Behavior |
|-------|------|----------|
| **V3-A** | Spawn GATE | Mediate `Task` / `spawn_subagent` / `SubagentStart` when harness fires it. Policy: allow/deny spawn by agent type, cwd, roots, optional max children. Signed journal row `action=spawn_agent`. |
| **V3-B** | Child hook inheritance | Ensure install wires the **same** LIA PreToolUse into subagent contexts when the harness supports it (Grok remaps Stop→SubagentStop; PreToolUse should still apply inside child). Probe + document per harness. |
| **V3-C** | Parent/child journal link | Propagate `parent_session_id` / `agent_id` / `spawn_receipt_id` into child gate rows when stdin provides them. `lia journal-verify` can show a tree summary (best-effort). |
| **V3-D** | Full tree PREVENT claim | **Only if** harness + probes prove child tools always hit LIA. Otherwise remain PARTIAL / CANNOT-OBSERVE for “full subagent visibility.” |

**Non-claim:** Orchestration, recovery after child fail, or “subagent cannot escape”
without process confine.

**Exit:** Spawn is gateable; child tools either GATE with linkage or honest CANNOT-OBSERVE;
assurance probe has a `subagent_visibility` key that can become true under measured conditions.

### W4 — Install, doctor, and false-deny prevention

**Problem:** Config is part of the TCB; bad defaults look like broken gates.

**Deliverables:**

- `lia doctor` (or `status --verbose`):
  - binary version vs install manifest
  - `allowed_roots` and whether home is included
  - hook command paths exist and point at current binary
  - sample envelope self-test (Claude + Grok JSON) → expect allow under home
  - billing/CI not required
- Preserve roots on reinstall (shipped 0.2.2); add **merge** of explicit
  `--allowed-root` with prior roots (union) when flag `--union-roots` set.
- Optional `LIA_ALLOWED_ROOTS` env for ephemeral CI.
- Install notes warn when roots exclude `$HOME` but Claude/Grok global hooks are live.
- Grok install surface: write `~/.grok` hooks **or** document `compat.claude.hooks`
  + tested Claude path (prefer dual: native Grok hook file + Claude compat).

**Exit:** Fresh install on a multi-project machine does not false-deny `ls $HOME` or
read under `$HOME/…`; doctor catches regressions.

### W5 — MCP mutation surface

**Problem:** MCP tools appear as `server__tool` and often miss matchers; mutations
bypass FS/shell gates.

**Deliverables:**

- Classify MCP tools: read-only inspect (existing) vs mutate (write/exec).
- Policy allowlist/denylist by server and tool name.
- Map known high-risk MCP tools onto FS/shell gates when args contain paths/commands.
- Codex path already proxies; align Cursor MCP pre-hook and Grok `use_tool` naming.

**Exit:** Documented MCP mediation mode; unknown mutate tools either deny (strict) or
CANNOT-OBSERVE with explicit reason (default).

### W6 — Measurement, claims, release

**Deliverables:**

- Probe keys: `grok_envelope`, `subagent_spawn_gate`, `subagent_child_tools`,
  `matcher_profile`.
- Recorded fixtures for Grok PreToolUse (no live cloud required).
- Optional live Grok session smoke script (operator-run).
- Claims lint entries for new PARTIAL cells.
- Public `v0.3.0` release: notes, package, install pin, preserve 0.2.x tags.
- Hosted IS-5 remains non-blocking if billing lock persists; local smoke required.

### W7 — Carry-over POST-L6 items (optional in V3 window)

Do **not** block 0.3.0 on these; schedule only if capacity remains:

| ID | Item | V3 stance |
|----|------|-----------|
| P3-1 | Second utility model lane | External/cost; keep DEFERRED |
| P3-7 | Live OAuth PREVENT | External credential gate |
| P3-8 | Funding | Owner-only |
| P3-4/10 | Confined wrap | Already SHIPPED-LOCAL; polish only |
| — | Windows/macOS CONFINE research | Doc-only |

---

## 7. Milestone sequence (implementation order)

Mirrors V2 discipline: RED fixtures → implement → independent audit → handoff commit.

| Milestone | Theme | Primary exit criteria |
|-----------|--------|------------------------|
| **M0** | Recon & freeze | Inventory harness events (Grok hooks doc, Claude, Cursor, Gemini, Codex). Freeze matcher profiles and spawn schema. Update this plan’s ledger with SHIPPED/MISSING. |
| **M1** | Envelope contract | Shared normalize + fixtures; all current adapters use it; Grok regressions stay green. |
| **M2** | Doctor + install polish | `lia doctor`; union-roots; Grok install path documented or wired; false-deny smoke in CI/local. |
| **M3** | Spawn GATE (V3-A) | Task/spawn_subagent / SubagentStart policy + journal; tests. |
| **M4** | Child mediation (V3-B/C) | Probe child PreToolUse; parent/child receipt fields; assurance key update. |
| **M5** | Matcher profiles + MCP | broad/strict profiles; MCP mutate policy; status shows coverage. |
| **M6** | Proof & 0.3.0 release | Workspace tests, conformance, claims lint, package, public release, one-liner `lia 0.3.0`. |

No production-source edit before M0 freeze. Each milestone ends with an auditor pass
and a handoff section (same convention as V2).

---

## 8. Requirement ledger (V3)

Statuses: `PLANNED` | `IN_PROGRESS` | `SHIPPED` | `SHIPPED-LOCAL` | `PARTIAL` | `DEFERRED` | `EXTERNAL-ONLY`.

### Ledger A — Operator trust (must for 0.3.0)

| ID | Intent | Acceptance | Target |
|----|--------|------------|--------|
| V3-0 | Multi-envelope parse is shared and tested | Claude + Grok + at least one other harness fixtures green | M1 |
| V3-1 | Distinct parse vs policy deny signals | Operator can tell ADAPTER_PARSE from FS/SHELL deny | M1 |
| V3-2 | `lia doctor` catches bad roots/hooks/binary skew | Failing fixture install → doctor non-zero + human text | M2 |
| V3-3 | Install does not shrink broader roots by default | Reinstall from clone preserves home roots (0.2.2+) + doctor | M2 |
| V3-4 | Spawn can be gated | Deny/allow spawn under policy with signed row | M3 |
| V3-5 | Status lists mediated vs unmediated tools | Snapshot matches install matcher profile | M2/M5 |
| V3-6 | Grok is a first-class compatibility row | harness-compatibility.md + install docs | M2 |
| V3-7 | Public 0.3.0 one-liner installs V3 | tag, assets, VERSION_HINT, `lia 0.3.0` | M6 |

### Ledger B — Agent tree (0.3.0 partial OK)

| ID | Intent | Acceptance | Target |
|----|--------|------------|--------|
| V3-10 | Child tools documented per harness | Table: child PreToolUse yes/no/unknown | M0/M4 |
| V3-11 | Parent/child journal linkage when ids present | Verify tree summary or linked receipt fields | M4 |
| V3-12 | `subagent_visibility` probe key | false → true only under measured harness proof | M4/M6 |
| V3-13 | Full subagent PREVENT claim | Only with green probe; else PARTIAL | M6 or DEFER |

### Ledger C — MCP & breadth (stretch inside V3)

| ID | Intent | Acceptance | Target |
|----|--------|------------|--------|
| V3-20 | Matcher profiles default/broad/strict-mcp | Install flag or config field | M5 |
| V3-21 | MCP mutate policy | Allowlist or deny-unknown mode tested | M5 |
| V3-22 | Grep/list_dir as optional FS-scope | Opt-in profile; default unchanged | M5 |

### Ledger D — External (not release-blocking)

| ID | Intent | Status |
|----|--------|--------|
| V3-30 | Live OAuth PREVENT | EXTERNAL-ONLY (P3-7) |
| V3-31 | Second utility lane cost run | DEFERRED (P3-1) |
| V3-32 | Funding applications | EXTERNAL-ONLY (P3-8) |
| V3-33 | Hosted two-runner IS-5 | PARTIAL until billing unlock |

---

## 9. Threat & residual boundaries (V3 still accepts)

Even after V3:

- Unhooked binary execution, editor @-reads, and non-tool side effects remain outside GATE.
- Same-UID credential theft remains outside Kernel.
- Child agents in a harness that **does not** run PreToolUse inside the child remain
  CANNOT-OBSERVE for child tools (spawn may still be gated).
- Linux confine remains opt-in wrap, not the default hook path.

Update `docs/guarantee-matrix.md` only when a cell actually moves; never “upgrade”
by documentation alone.

---

## 10. Release train

| Artifact | Rule |
|----------|------|
| SemVer | `0.3.0` for the V3 feature release; patches `0.3.x` for envelope/install hotfixes |
| Tag | `v0.3.0` |
| Assets | Linux x86_64 tarball + SHA256SUMS (same contract as 0.2.x) |
| Installer | `VERSION_HINT=0.3.0`; keep fail-closed checksum path |
| Notes | `docs/releases/v0.3.0.md` — highlights + honest limitations |
| Preserve | All prior tags `v0.1.0` … `v0.2.2` |

Suggested marketing line (honest):

> **0.3.0 — Multi-harness mediation depth:** Grok-class envelopes, install doctor,
> optional spawn gating, and clearer subagent visibility — still GATE, not complete
> mediation.

---

## 11. Suggested first implementation slice (when starting V3)

If capacity is one PR train only, do **M0 + M1 + M2** before spawn:

1. Freeze harness event matrix (Grok `SubagentStart`/`PreToolUse` vs Claude).
2. Extract shared envelope normalize; delete reliance on ad-hoc wrapper Python.
3. Ship `lia doctor` + false-deny smoke (Grok camelCase allow under `$HOME`, OOS deny).
4. Then M3 spawn GATE.

That order maximizes operator value (stop false denies, explain mediation) before
multi-agent complexity.

---

## 12. Open decisions (resolve in M0)

1. **Native Grok adapter vs Claude-compat only?**  
   Recommendation: keep Claude-compat working; add thin `grok` adapter only if
   Grok decision JSON (`{decision,reason}`) must be emitted without Claude
   `hookSpecificOutput` shape.
2. **Default matcher profile after V3?**  
   Recommendation: keep `default` for least surprise; offer `broad` via
   `lia install --matcher-profile broad`.
3. **Default spawn policy?**  
   Recommendation: allow spawn (compat) but journal it; optional
   `deny_spawn_outside_roots` and `max_children`.
4. **Should MCP unknown mutate fail-closed by default?**  
   Recommendation: no (too noisy); strict profile yes.

Record decisions in the future V3 handoff M0 section.

---

## 13. References

- Diagnosis: `work_games/workflow/reasoning/lia-grok-tool-block-diagnosis-2026-07-24.md`
- V2 handoff: `docs/V2-IMPLEMENTATION-HANDOFF.md`
- Roadmap carry-overs: `docs/roadmap.md`
- Guarantees: `docs/guarantee-matrix.md`, `docs/threat-model.md`
- Harness table: `docs/harness-compatibility.md`
- Releases: `docs/releases/v0.2.1.md`, `v0.2.2.md`

---

## 14. One-page backlog (copy into issues)

- [ ] V3-M0: harness event matrix + freeze spawn schema  
- [ ] V3-0/1: shared envelope normalize + parse reason codes  
- [ ] V3-2/3/6: doctor + install/Grok docs  
- [ ] V3-4: spawn GATE  
- [ ] V3-10/11/12: child mediation probe + journal link  
- [ ] V3-5/20/21: matcher profiles + MCP mutate policy  
- [ ] V3-7: public `v0.3.0` release  

**Plan owner:** Kernel maintainers  
**Next action when authorized:** open `docs/V3-IMPLEMENTATION-HANDOFF.md` and start M0.
