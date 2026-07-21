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
  and evidence-drop are caught).
- **Does (with an external anchor):** authenticity — that a bundle was produced by a
  signer you pinned (`lia verify --trust-root <path>` / `--require-authenticity`).
- **Does not:** authenticity WITHOUT a pinned key (the in-bundle trust-root is
  self-asserted, so integrity-only verify proves consistency, not who signed);
  complete process confinement; network egress PREVENT; protection when the host
  harness never invokes the hook/MCP path; a signing key against an agent sharing the
  operator's uid.

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
   readable by the agent (this is why v1 tops out at GATE, not CONFINE).
5. Never claim CONFINE or complete mediation for Claude Code / Codex in v1.
6. Do not pool recorded and live MEASURED catch metrics in public docs.

## Supply chain

- License: Apache-2.0 (`LICENSE`, `deny.toml` allowlist).
- Prefer release builds: `cargo build -p lia-cli --release`.
- Optional public-log path (cosign) is POST-L6 / not required for offline Ed25519 verify.
