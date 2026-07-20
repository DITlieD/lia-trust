# LIA Trust Kernel — threat model (v1)

## Assets

| Asset | Why it matters |
|-------|----------------|
| Host workspace / repo files | Agent tools can delete, overwrite, or exfiltrate |
| Trust journal + receipts | Integrity of “what happened” for offline audit |
| Policy / gate rules | Must stay frozen for a run (freeze-the-gate) |
| Signing keys | Authenticity of receipts (Ed25519) |
| Operator confidence | False MEASURED numbers are product-breaking (HL-6) |

## Adversaries

1. **Untrusted agent model** — fabricates test pass, deletes out of scope, invents deps, agrees with false premises, leaks secrets.
2. **Compromised or buggy harness adapter path** — hooks not fired, MCP bypassed, tools outside mediation.
3. **Post-hoc journal tamperer** — reorders/removes rows or swaps evidence after the fact.
4. **Marketing / doc drift** — claims PREVENT or CONFINE without probe-backed cells.

## Trust boundary (Kernel TCB)

In scope for v1 Kernel:

- Protocol events + seven gates (rules-as-data, fail-closed)
- Append-only journal + blake3 chain + Ed25519 receipts
- Offline `lia verify` / `journal-verify`
- Thin adapters: Claude Code **PreToolUse** hook, Codex **MCP** proxy, generic wrap (honest partial mediation)

Out of scope (not Kernel / commercial LIA or POST-L6):

- Planning, recovery, multi-agent orchestration, claim extraction
- Process/network **CONFINE**, credential broker, live package registries
- Commercial Harness / Canvas product layers

## Attack → control map

| Attack | Control | Residual |
|--------|---------|----------|
| Fabricated test pass | test-integrity gate on hook/MCP/wrap path | Only when action hits adapter |
| `rm -rf` / OOS delete | shell-irreversible + filesystem-scope | Nested shells / non-tool paths CANNOT-OBSERVE |
| Hallucinated dependency | dependency-reality (fixture registry in v1) | Live registry fetch POST-L6 |
| Unsupported agreement | lia-syco when invoked | Not on every Terminus path |
| Journal rewrite | journal-tamper + offline verify | Verifier must be run off-agent |
| Bypass hooks | Assurance honesty: GATE not CONFINE | Complete mediation **not claimed** |
| Secret in logs | secret-output when payload observed | Not all free-text agent stdout |

## Install attack surface

`lia install` writes harness config and a state dir under `~/.lia-trust` (or `--lia-home`):

- Hook/MCP wrappers read signing key from a **0600** file (not from settings.json argv).
- Live `~/.claude` / `~/.codex` require explicit `--apply-live`.
- Uninstall removes only LIA-marked entries.

## Non-goals / non-guarantees

See `docs/guarantee-matrix.md`. v1 never claims CONFINE, complete mediation, or network egress PREVENT.
