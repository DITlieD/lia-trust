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
| Opt-in IP-egress CONFINE | attested fresh network namespace with no external interface | one `lia wrap --linux-confine` process on a supported Linux host |
| Opt-in path-write CONFINE | private mount namespace + read-only evidence bind + Landlock write allow-rule only below worktree | one attested confined wrap; pre-opened descriptors excluded |
| Scoped credential delivery | private single-link source, exact-path mask, one-shot expiring FD broker | one attested confined wrap; same-uid global secrecy not claimed |

## Non-guarantees (honest CANNOT-OBSERVE / deferred)

| Non-guarantee | Why | Where to buy / wait |
|---------------|-----|---------------------|
| Complete mediation | Hooks/MCP are bypassable without process confine | LIA / POST-L6 CONFINE |
| Network egress PREVENT for hook/MCP or unwrapped processes | Hooks have no egress boundary | Use the opt-in Linux wrapper or a host sandbox |
| Every network/IPC transport | Fresh netns blocks IP; this backend does not install Landlock network/IPC rights, so pathname Unix sockets remain outside the claim | Separate IPC policy / host sandbox |
| Credential secrecy from the same OS uid | Exact source is masked, but other same-uid processes and undeclared hard paths remain outside the boundary | Separate principal / keystore |
| Registry response transparency-log authenticity | HTTPS observation is not a registry-signed statement | External registry transparency/signature system |
| Subagent full visibility | Partial keys only | LIA multi-agent |
| Auto-repair after deny | Closed (LIA) | Commercial Harness |
| Claim extraction from free text | Closed (LIA) | Commercial Harness |
| Cross-platform CONFINE | Linux backend only | Windows/macOS backend research |
| Byte-replay of cloud model | Trace-authenticated only (HL-3) | N/A |

## Upsell pointer

`docs/upsell.md` — commercial product fills CANNOT-OBSERVE cells Kernel
documents honestly. Kernel remains useful **without** the commercial harness
via install + offline verify.
