# Security policy

## Supported versions

| Version | Supported |
|---------|-----------|
| `main` / unreleased 0.1.x | Yes (best effort) |
| Pre-release tags | Best effort while maintained |

## Reporting a vulnerability

Please report security issues **privately** (do not open a public issue with
exploit detail):

1. Prefer an encrypted channel if available (email to maintainers once published).
2. Include: affected component (`lia` CLI, gate id, adapter path), reproduction,
   and impact (false-open, journal forge, key exposure).
3. Allow reasonable time for a fix before public disclosure.

## What LIA guarantees (and does not)

- **Does:** fail-closed gates on actions that reach the adapter boundary;
  signed journal rows; offline verify recomputes the chain from bytes and detects
  tamper; a signed manifest seal binds the evidence list + row count (tail-truncation
  and evidence-drop are caught); typed process completion is bound to a signed,
  contract-scoped execution-manifest digest.
- **Does (with an external anchor):** authenticity — that a bundle was produced by a
  signer you pinned (`lia verify --trust-root <path>` / `--require-authenticity`).
- **Does (only for an attested `lia wrap --linux-confine` run on a supported Linux host):**
  deny IP egress in a fresh network namespace; deny filesystem-path writes outside the writable
  worktree using a recursively read-only mount tree plus Landlock; make the evidence directory
  read-only; and expose declared credentials through one-shot, expiring descriptor brokers.
- **Does not:** authenticity WITHOUT a pinned key (the in-bundle trust-root is
  self-asserted, so integrity-only verify proves consistency, not who signed);
  complete mediation; filesystem-read confinement; every IPC transport (including pathname Unix
  sockets); protection when a hook/MCP harness never invokes LIA; or a signing key/credential
  source against another process sharing the operator's uid. Hook/MCP and ordinary wrap paths do
  not inherit the optional Linux boundary.

See `docs/threat-model.md` (Authenticity vs integrity, Known limitations) and
`docs/guarantee-matrix.md`.

## Hardening expectations for operators

1. Install with `lia install` so state lives under `~/.lia-trust` (mode 0600 keys).
2. Keep the `lia` binary and wrappers outside agent write roots.
3. Run `lia journal-verify` / `lia verify` off-agent after sensitive sessions, and pass
   `--trust-root` (or `--require-authenticity` for a third-party bundle) so verify
   checks authenticity, not just integrity.
4. If you need a hard guarantee against the *agent itself* forging journal rows, run the
   signer under a SEPARATE uid/principal the agent cannot read — a same-uid 0600 key is
   readable by the agent. The optional Linux wrapper does not create a separate signing principal.
5. Never claim CONFINE or complete mediation for any hook/MCP adapter. Treat Linux confinement as
   per-run evidence: require `confinement-report-<run_id>.json`, its signed journal event, and its
   process-contract evidence binding.
6. For `--linux-confine`, pin the canonical root-owned, non-group/world-writable `unshare` helper by
   SHA-256 and keep that pin outside agent write roots. Do not run the wrapper as euid 0 when helper
   ownership is part of the trust decision; root cannot meaningfully prove the helper is owned by a
   different, less-privileged principal.
7. Credential sources must be current-owner private, non-symlink, single-link files outside the
   worktree. Use a separate OS principal or keystore if other same-uid processes are adversarial.
8. Do not pool recorded and live MEASURED catch metrics in public docs.

## Supply chain

- License: Apache-2.0 (`LICENSE`, `deny.toml` allowlist).
- Prefer release builds: `cargo build -p lia-cli --release`.
- Optional public-log verification delegates to an operator-pinned `cosign` executable and requires
  pinned certificate identity + issuer. The report records verifier/artifact/bundle digests; it is
  not itself a signed receipt unless the operator journals or bundles it.
- Live dependency evidence is restricted to the official crates.io/npm HTTPS origins, disables
  redirects, and requires a pinned HTTP-client digest. Offline cache acceptance requires external
  response + metadata pins and a freshness bound.
- Digest checking cannot stop same-UID TOCTOU replacement by an agent that controls the executable or
  evidence paths. Keep pins and verified bytes outside agent write roots; stronger principal/process
  isolation is a separate confinement layer.
