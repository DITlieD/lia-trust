# Guarantee / non-guarantee matrix

Mechanical upsell of assurance cells: what Kernel **can** enforce today vs what
requires commercial / POST-L6 surfaces. Source capability rollup:
`bench/assurance_truth.json`, probe via `bench/probe_assurance.sh`,
`lia report --adapter <name> --probe <file>`.

## Guarantees (v1 Kernel, when installed and path fires)

| Guarantee | Mechanism | Harnesses |
|-----------|-----------|-----------|
| Fabricated pass REFUTED | test-integrity on claimed_pass without wrapper observation | Claude hook, Codex MCP, generic live loop |
| Destructive shell DENY | shell-irreversible after expansion-aware checks | Claude, Codex, Gemini, and Cursor mapped shell paths |
| Out-of-scope path DENY | filesystem-scope against `allowed_roots` | Write/Edit/Delete + delete_file |
| Signed journal row | Ed25519 over gate outcome | All journaling adapters |
| Offline recompute | `lia journal-verify` / `lia verify` | Any run with journal/bundle |
| Fail-closed policy | missing evidence → deny/incomplete | Seven gates |
| Process-terminal binding | pre-action contract receipt + signed execution-manifest digest | `process-contract-validate`, generic wrap |
| Optional public blob check | digest-pinned external cosign + identity/issuer pins + input hashes | `public-verify` |
| Bounded dependency observation | fixed official HTTPS origins + pinned client; pinned/fresh offline replay | `registry-evidence` for crates.io/npm |

## Non-guarantees (honest CANNOT-OBSERVE / deferred)

| Non-guarantee | Why | Where to buy / wait |
|---------------|-----|---------------------|
| Complete mediation | Hooks/MCP are bypassable without process confine | LIA / POST-L6 CONFINE |
| Network egress PREVENT | No egress hook in Claude/Codex v1 | POST-L6 / host sandbox |
| Credential broker | Not in Kernel | POST-L6 |
| Registry response transparency-log authenticity | HTTPS observation is not a registry-signed statement | External registry transparency/signature system |
| Subagent full visibility | Partial keys only | LIA multi-agent |
| Auto-repair after deny | Closed (LIA) | Commercial Harness |
| Claim extraction from free text | Closed (LIA) | Commercial Harness |
| CONFINE / namespaces | Forbidden claim in v1 | POST-L6 |
| Byte-replay of cloud model | Trace-authenticated only (HL-3) | N/A |

## Upsell pointer

`docs/upsell.md` — commercial product fills CANNOT-OBSERVE cells Kernel
documents honestly. Kernel remains useful **without** the commercial harness
via install + offline verify.
