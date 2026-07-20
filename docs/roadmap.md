# LIA Trust roadmap (post-L6 tracked items)

## Shipped (Kernel install + L5 adapter paths + L6 pack)

- `lia install` / `status` / `uninstall` for Claude Code + Codex
- PREVENT recorded-adapter MEASURED lanes for `claude-code` and `codex`
- L6 docs: threat model, SECURITY, CONTRIBUTING, COC, harness table, guarantee matrix, CONTRACTS.md

## Fast-follows (POST-L6 / deferred)

| ID | Item | Status | Notes |
|----|------|--------|-------|
| P3-1 | Second free-model Harbor utility lane | **DEFERRED** | After livability fix; only swe-1-6 MEASURED today |
| P3-4 | Network/egress CONFINE | **POST-L6** | v1 remains CANNOT-GUARANTEE; no CONFINE claim |
| P3-5 | Gemini CLI + Cursor adapters | **POST-L6** | Tracked only; no fake MEASURED |
| P3-6 | Full typed process-contract validator | **POST-L6** | v1 ships completion half (evidence-completeness) only |
| P3-7 | Live Claude Code / Codex agent PREVENT (OAuth harness) | **PARTIAL** | Recorded-adapter MEASURED; live free-bridge optional |
| P3-8 | L7 funding applications | **POST-RELEASE** | See `docs/programs.md` |
| P3-9 | Optional cosign public-log verify | **POST-L6** | HL-5 |
| P3-10 | Linux namespaces CONFINE backend | **POST-L6** | Never claim until shipped |

Do not mark these MEASURED until a Harbor/probe lane exists.
