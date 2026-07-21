# LIA Trust Kernel — threat model

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

In scope for the current Kernel:

- Protocol events + seven gates (rules-as-data, fail-closed)
- Append-only journal + blake3 chain + Ed25519 receipts
- Offline `lia verify` / `journal-verify`
- Typed process-contract validation with signed pre-action declaration and terminal execution manifest
- Thin adapters: Claude Code **PreToolUse**, Codex **MCP**, Gemini CLI **BeforeTool**, Cursor
  fail-closed shell/MCP hooks, and generic wrap (honest partial mediation)
- Optional digest-pinned external cosign verification and official-origin dependency observations
- Optional Linux `lia wrap --linux-confine`: attested namespaces, recursively read-only host mount
  tree with a writable worktree submount, Landlock write policy, capability drop, signed per-run
  evidence, and one-shot expiring credential descriptors

Out of scope (not Kernel / commercial LIA or POST-L6):

- Planning, recovery, multi-agent orchestration, claim extraction
- Cross-platform or complete process/network **CONFINE**
- Filesystem-read confinement, every local IPC transport, and separate-principal credential custody
- Commercial Harness / Canvas product layers

## Attack → control map

| Attack | Control | Residual |
|--------|---------|----------|
| Fabricated test pass | test-integrity gate on hook/MCP/wrap path | Only when action hits adapter |
| `rm -rf` / OOS delete | shell-irreversible + filesystem-scope | Denylist is best-effort (see below); nested shells / non-tool paths CANNOT-OBSERVE |
| Hallucinated dependency | dependency-reality from policy snapshot or bounded official-registry evidence | HTTPS observation is not registry-signed transparency proof |
| Unsupported agreement | lia-syco when invoked | Not on every Terminus path |
| Journal rewrite (tamper) | blake3 chain recompute + Ed25519, offline verify | Verifier must be run off-agent |
| Journal forge (attacker's own keys) | **external trust anchor** (`--trust-root`) | Integrity-only without a pinned key (see Authenticity) |
| Journal tail-truncation / evidence drop | signed MANIFEST + row-count seal | Legacy unsealed bundles verify integrity-only |
| Post-hoc process contract / receipt reuse | signed contract declaration before actions + contract-scoped terminal manifest digest | Same-UID signer-key compromise can still forge |
| Fake verifier/client helper | operator-pinned executable digest; official registry origins only | Same-UID TOCTOU/dynamic dependency replacement; operator can deliberately pin an untrusted helper |
| Offline registry cache rewrite | external response + metadata digest pins and max-age policy | Pin storage must remain outside agent write roots |
| Wrapped process opens an IP connection | attested fresh network namespace with no external interface | Only the opt-in confined process; pathname Unix sockets and pre-opened descriptors are separate |
| Wrapped process mutates host/evidence paths | recursive read-only mount tree + writable worktree submount + Landlock ABI 3 write restrictions | Path-based writes only; pre-opened descriptors and kernel/host compromise are outside the claim |
| Agent reads a declared credential source | exact source bind-mask + one-shot expiring FD broker with locked/zeroed buffer | Other same-uid processes and undeclared aliases/hard paths require a separate principal |
| Agent starts before confinement evidence exists | child attestation handshake; parent persists, hashes, journals, and contract-binds the report before `GO` | Trusts the pinned helper, wrapper, kernel, and protected signing/evidence paths |
| Bypass hooks | Assurance honesty: GATE not CONFINE | Complete mediation **not claimed** |
| Secret in logs | secret-output when payload observed | Regex set is non-exhaustive; not all free-text agent stdout |

## Authenticity vs integrity (what `lia verify` proves)

`lia verify` proves two different things, and conflating them is a trust error:

- **Integrity** (always): the bundle is internally self-consistent and untampered since it
  was signed — the blake3 chain recomputes from the event bytes, the manifest seal holds,
  the Ed25519 signatures verify. This needs nothing outside the bundle.
- **Authenticity** (only with an external anchor): the bundle was produced by a signer you
  trust. The in-bundle `trust-root.json` is supplied by whoever made the bundle, so alone it
  proves nothing about *who* — an attacker can mint a fully self-consistent bundle with their
  own keys. To establish authenticity, pin the expected signer out-of-band:
  `lia verify <bundle> --trust-root <path>` (defaults to `~/.lia-trust/trust-root.json`),
  and use `--require-authenticity` when verifying a bundle you did not produce. Without an
  anchor the report is `authenticated: false` / `authenticity: "self-rooted"` and says so.

## Known limitations (disclosed, not hidden)

- **Same-uid key and credential exposure.** The signing key lives at `~/.lia-trust/keys/…` mode 0600. A
  wrapped agent that shares the operator's uid (Claude Code / Codex run as the user) can read
  it and forge authentic-looking journal rows. 0600 does not defend against the same uid.
  The optional broker masks an exact declared credential path inside its mount namespace, but
  neither it nor 0600 protects against another adversarial same-uid process. For a hard guarantee,
  run the signer and credential source under a separate principal the agent cannot read.
- **Linux confinement is deliberately narrow.** A successful per-run attestation supports IP-egress
  and filesystem-path-write CONFINE for that wrapped process. It does not confine host filesystem
  reads, pathname Unix sockets, pre-opened file descriptors, or out-of-band processes. Unsupported
  namespaces, Landlock ABI below three, helper drift, mount failure, or memory-lock failure stop
  before the agent is released.
- **Shell gate is a best-effort denylist, not a complete classifier.** It denies a curated,
  adversarially-tested set of irreversible shapes (recursive delete incl. `find -exec`/`xargs`,
  `truncate -s 0`, `chmod -R 000`, force-push, publish, fork bomb, pipe-to-interpreter, power
  control, command/process substitution, …) and fails closed on any internal error, but a
  novel destructive one-liner outside the set can pass. New shapes are added as fixtures; the
  set is not claimed exhaustive.
- **Secret detector is regex-based.** Broad coverage (PEM private keys, AWS/GitHub/Slack/
  OpenAI/Anthropic/Google/Stripe tokens, JWTs, URI credentials) but a novel secret shape can
  slip; the shareable bundle projection is structurally hash-only regardless.
- **External verifier trust is explicit, not magical.** `public-verify` proves what the
  digest-pinned `cosign` process reported for the hashed paths; it does not authenticate the cosign
  binary's provenance for you. Registry evidence similarly depends on the operator's pinned client,
  platform CA store, and protected external cache pins. Same-UID replacement races remain until a
  stronger principal boundary exists. The Linux wrapper checks the helper before and immediately
  after spawn, but same-UID replacement of other trusted executable/dependency paths remains a host
  hardening concern.

## Install attack surface

`lia install` writes harness config and a state dir under `~/.lia-trust` (or `--lia-home`):

- Hook/MCP wrappers read signing key from a **0600** file (not from settings.json argv).
- Live `~/.claude`, `~/.codex`, `~/.gemini`, and `~/.cursor` require explicit `--apply-live`.
- Uninstall removes only LIA-marked entries.

## Non-goals / non-guarantees

See `docs/guarantee-matrix.md`. Hook/MCP adapters never claim CONFINE. Only a successful, signed
`lia wrap --linux-confine` report supports the narrow IP-egress and filesystem-path-write cells;
complete mediation, read confinement, every IPC transport, and same-principal secrecy remain
non-guarantees.
