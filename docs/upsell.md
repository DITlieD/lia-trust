# LIA Trust — what you get (v1, claims-lint clean)

LIA sits on the agent action path and **prevents** unsafe or unsupported
actions when the corresponding gate is wired:

- Fabricated test passes without HL-4 wrapper observation
- Completing work without required evidence
- Out-of-scope filesystem writes/deletes
- Irreversible shell (`rm -rf /`, force-push, pipe-to-shell, …)
- Hallucinated dependencies against a policy snapshot or supplied official-registry evidence
- Secret material in shareable outputs
- Journal tamper probes (chain breaks)

**Grounding and sycophancy detection** are on the trust live-tool-loop path.
They are **not** on Harbor TerminusLia (TB2/Claw) until that adapter is
extended — see `docs/claims.json` honesty entries.

**Not claimed:** complete mediation / CONFINE for any hook/MCP adapter or ordinary
generic wrap; cross-platform confinement; that trust automatically raises SWE pass-rate. The
opt-in Linux wrapper has narrower, per-run attested IP/path-write cells and does not close the full
commercial isolation boundary.

## Mechanical gap list (from assurance cells)

| CANNOT-OBSERVE / non-guarantee | Kernel status | Commercial / POST-L6 fill |
|--------------------------------|---------------|---------------------------|
| Complete mediation | GATE only (hooks/MCP); optional wrapper is still not complete mediation | Process supervisor + full sandbox |
| Network egress PREVENT | opt-in Linux wrap blocks IP egress for one attested process; hooks/unwrapped and non-IP IPC remain open | Cross-platform host/network sandbox |
| Credential broker | scoped one-shot FD delivery; no separate-principal custody or general secret service | Keystore-backed broker product surface |
| Registry-signed/transparency authenticity | bounded official HTTPS observation only | Registry transparency/signature integration |
| Claim extraction from free text | closed (LIA) | Harness reasoning layer |
| Auto-repair after gate fail | closed (LIA) | Harness recovery |
| Planning / multi-agent recovery | closed (LIA) | Harness / Canvas |
| Complete Gemini / Cursor mediation | mapped native hooks shipped locally | Confined process/tool supervisor |

See `docs/guarantee-matrix.md` and `bench/assurance_truth.json`.
