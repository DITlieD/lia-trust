# LIA Trust roadmap (post-L6 tracked items)

## V3 (planned)

Multi-harness mediation depth, install/doctor false-deny prevention, spawn/child
agent visibility, and MCP matcher honesty — target public `v0.3.0`.

→ **Plan:** [`docs/V3-IMPROVEMENT-PLAN.md`](V3-IMPROVEMENT-PLAN.md)

Baseline: `v0.2.2` (V2 complete + Grok envelope + install `$HOME` roots).

## Shipped (Kernel install + L5 adapter paths + L6 pack)

- `lia install` / `status` / `uninstall` for Claude Code, Codex, Gemini CLI, and Cursor
- PREVENT recorded-adapter MEASURED lanes for `claude-code` and `codex`
- Gemini CLI / Cursor pre-action adapters with local conformance and signed-denial integration
- `lia-process-contract-v1` with pre-action declaration and signed terminal execution manifest
- digest-pinned optional cosign verification and bounded official crates.io/npm evidence
- opt-in Linux namespace/Landlock wrapper with signed per-run IP/path-write confinement evidence and
  one-shot expiring credential descriptors
- L6 docs: threat model, SECURITY, CONTRIBUTING, COC, harness table, guarantee matrix, CONTRACTS.md

## Fast-follows (POST-L6 / deferred)

| ID | Item | Status | Notes |
|----|------|--------|-------|
| P3-1 | Second free-model Harbor utility lane | **DEFERRED** | After livability fix; only swe-1-6 MEASURED today |
| P3-4 | Network/egress CONFINE | **SHIPPED-LOCAL** | Fresh network namespace blocks IP egress for one attested `--linux-confine` process; hook adapters and non-IP IPC do not inherit it |
| P3-5 | Gemini CLI + Cursor adapters | **SHIPPED-LOCAL** | Native documented config/hook paths and local conformance; live harness runs remain unmeasured |
| P3-6 | Full typed process-contract validator | **SHIPPED-LOCAL** | Contract/action/evidence/assumption/claim/outcome state is manifest-bound; planner remains outside Kernel |
| P3-7 | MCP inspection/live agent PREVENT | **PARTIAL** | Read-only inspection conformance shipped; live OAuth agents remain external |
| P3-8 | L7 funding applications | **POST-RELEASE** | See `docs/programs.md` |
| P3-9 | Optional cosign public-log verify | **SHIPPED-LOCAL** | Digest-pinned external verifier path + fixtures; no live public-log claim |
| P3-10 | Linux namespaces CONFINE backend | **SHIPPED-LOCAL** | Runtime-proven locally for namespaces, recursive host/evidence path-write denial, writable worktree, fail-closed setup, and scoped credential FD; reads/same-uid/Unix-socket residuals explicit |

`SHIPPED-LOCAL` means the local production-path suite is measured; it is not a Harbor utility result,
cross-platform result, hook-adapter guarantee, or live cloud-agent measurement.
