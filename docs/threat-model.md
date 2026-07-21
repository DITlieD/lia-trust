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
- Typed process-contract validation with signed pre-action declaration and terminal execution manifest
- Thin adapters: Claude Code **PreToolUse**, Codex **MCP**, Gemini CLI **BeforeTool**, Cursor
  fail-closed shell/MCP hooks, and generic wrap (honest partial mediation)
- Optional digest-pinned external cosign verification and official-origin dependency observations

Out of scope (not Kernel / commercial LIA or POST-L6):

- Planning, recovery, multi-agent orchestration, claim extraction
- Process/network **CONFINE** and credential broker
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

## Known limitations (v1, disclosed not hidden)

- **Same-uid key exposure.** The signing key lives at `~/.lia-trust/keys/…` mode 0600. A
  wrapped agent that shares the operator's uid (Claude Code / Codex run as the user) can read
  it and forge authentic-looking journal rows. 0600 does not defend against the same uid.
  For a hard guarantee, run the signer under a separate principal the agent cannot read; a
  broker/keystore is a POST-L6 fast-follow. This is why the assurance ceiling is GATE, not
  CONFINE.
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
  stronger principal/confinement boundary exists.

## Install attack surface

`lia install` writes harness config and a state dir under `~/.lia-trust` (or `--lia-home`):

- Hook/MCP wrappers read signing key from a **0600** file (not from settings.json argv).
- Live `~/.claude`, `~/.codex`, `~/.gemini`, and `~/.cursor` require explicit `--apply-live`.
- Uninstall removes only LIA-marked entries.

## Non-goals / non-guarantees

See `docs/guarantee-matrix.md`. v1 never claims CONFINE, complete mediation, or network egress PREVENT.
