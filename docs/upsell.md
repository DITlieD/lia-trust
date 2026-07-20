# LIA Trust — what you get (v1, claims-lint clean)

LIA sits on the agent action path and **prevents** unsafe or unsupported
actions when the corresponding gate is wired:

- Fabricated test passes without HL-4 wrapper observation
- Completing work without required evidence
- Out-of-scope filesystem writes/deletes
- Irreversible shell (`rm -rf /`, force-push, pipe-to-shell, …)
- Hallucinated dependencies against a registry snapshot
- Secret material in shareable outputs
- Journal tamper probes (chain breaks)

**Grounding and sycophancy detection** are on the trust live-tool-loop path.
They are **not** on Harbor TerminusLia (TB2/Claw) until that adapter is
extended — see `docs/claims.json` honesty entries.

**Not claimed in v1:** complete mediation / CONFINE for Claude Code, Codex, or
generic wrap; network egress confinement; that trust automatically raises SWE
pass-rate.

## Mechanical gap list (from assurance cells)

| CANNOT-OBSERVE / non-guarantee | Kernel status | Commercial / POST-L6 fill |
|--------------------------------|---------------|---------------------------|
| Complete mediation | GATE only (hooks/MCP) | Process supervisor + CONFINE |
| Network egress PREVENT | capability key false | Host/network sandbox |
| Credential broker | missing | Broker product surface |
| Live registry dependency fetch | fixture only | Registry integration |
| Claim extraction from free text | closed (LIA) | Harness reasoning layer |
| Auto-repair after gate fail | closed (LIA) | Harness recovery |
| Planning / multi-agent recovery | closed (LIA) | Harness / Canvas |
| Gemini / Cursor adapters | POST-L6 | Adapter pack |

See `docs/guarantee-matrix.md` and `bench/assurance_truth.json`.
