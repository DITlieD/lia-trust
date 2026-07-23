# LIA Trust Kernel

Fail-closed trust gates for agent actions: journaled decisions, policy-as-data,
and offline verify. Product metric is **TRUST-INTEGRITY** (catch / residual /
false-block on the trust corpus), not utility pass-rate.

**Kernel** (this repo) is the installable TCB: protocol + journal + Ed25519
receipts + seven gates + offline verify + thin adapters. It is **not** the
commercial Harness / Canvas product layers.

## One-line install (recommended)

Install the current stable release (`v0.2.1`):

```bash
curl -fsSL https://raw.githubusercontent.com/DITlieD/lia-trust/main/install.sh | bash
```

The installer downloads the checksum-verified Linux x86_64 release binary. If that asset is
unavailable or the platform is unsupported, `auto` mode builds the same `v0.2.1` tag from source;
checksum or archive verification failures never fall back.

From a clone, force a source build of the release version:

```bash
LIA_INSTALL_MODE=source bash install.sh
```

That script will:

1. Install verified `lia 0.2.1` from the `v0.2.1` release, or build that version from source
2. Install the binary to `~/.local/bin/lia`
3. Wire **Claude Code**, **Codex**, **Gemini CLI**, and **Cursor** with `lia install --apply-live`

### Installer knobs (env)

| Env | Effect |
|-----|--------|
| `LIA_NO_WIRE=1` | Binary only — do not touch harness configuration |
| `LIA_DRY_RUN=1` | Plan harness merge only |
| `LIA_PREFIX=~/.local` | Install prefix (`bin/lia`) |
| `LIA_INSTALL_MODE=auto` | Prefer verified prebuilt; source fallback only when unavailable/unsupported |
| `LIA_INSTALL_MODE=prebuilt` | Require the verified release asset; never build from source |
| `LIA_INSTALL_MODE=source` | Build the pinned release tag from source |
| `LIA_FORCE_BUILD=1` | Always rebuild |

Examples:

```bash
# binary only
LIA_NO_WIRE=1 bash install.sh

# verified prebuilt only
LIA_NO_WIRE=1 LIA_INSTALL_MODE=prebuilt bash install.sh

# dry-run harness wiring
LIA_DRY_RUN=1 bash install.sh
```

### After install

```bash
lia status
# claude_hook_installed: true
# codex_mcp_installed: true
# gemini_hook_installed: true
# cursor_hooks_installed: true
# assurance: GATE … never CONFINE

lia journal-verify ~/.lia-trust/journal/default.db
lia uninstall --apply-live    # remove wiring; keeps journal/keys
```

### Manual (no install.sh)

```bash
cargo build -p lia-cli --release
./target/release/lia --version  # lia 0.2.1
./target/release/lia install --apply-live
```

The [`v0.2.1` release](https://github.com/DITlieD/lia-trust/releases/tag/v0.2.1) ships a verified
Linux x86_64 binary and `SHA256SUMS`. Other targets use the pinned source fallback and require
Rust plus Git; they are not presented as prebuilt-verified platforms.

What install does:

| Target | Wiring |
|--------|--------|
| Claude Code | `~/.claude/settings.json` → PreToolUse hook → `lia hook` |
| Codex | `~/.codex/config.toml` → `[mcp_servers.lia-trust]` → `lia mcp` |
| Gemini CLI | `~/.gemini/settings.json` → BeforeTool hook → `lia hook` |
| Cursor | `~/.cursor/hooks.json` → fail-closed shell/MCP hooks → `lia hook` |
| State | `~/.lia-trust/` keys, journal, policy, wrappers |

Enforced only where hooks/MCP fire (**GATE**). Not complete mediation; not CONFINE.

See `docs/CONTRACTS.md`, `docs/harness-compatibility.md`, `docs/threat-model.md`.

### Process and external-evidence verification

`lia process-contract-validate` checks a versioned task contract against a pre-action contract
receipt and a signed terminal manifest. Evidence kinds and digests, allowed actions, assumption
support, unresolved claims, and honest-stop unblock data are all contract-scoped. The Kernel
validates a supplied process contract; it does not plan or repair the task.

`lia public-verify` delegates to a **digest-pinned** `cosign verify-blob` and records the artifact,
bundle, and verifier hashes. `lia registry-evidence` accepts live results only from the fixed
official crates.io/npm HTTPS origins through a digest-pinned client. Offline registry replay needs
external pins for both the response and cache metadata and enforces a maximum cache age. See
`docs/CONTRACTS.md` for the exact flags and residual same-UID/TOCTOU limits.

### Bounded execution and journal lifecycle

Generic wrapped processes have an explicit deadline (15 minutes by default):

```bash
lia wrap --repo ./repo --evidence-dir /safe/evidence --config gate-config.json \
  --secret-key-hex "$LIA_SECRET" --timeout-seconds 900 -- agent-command
```

On deadline, LIA terminates the directly wrapped child, records
`GENERIC_AGENT_TIMEOUT`, and exits 124 after writing the observed result and final-diff evidence.
This is bounded wrapper ownership, not descendant-process or network confinement. The nominal
deadline does not override cleanup safety: if the OS refuses to kill or reap the direct child, LIA
stays fail-stop and keeps retrying with bounded diagnostic state instead of returning while that
child may still be live.

### Opt-in Linux confinement and scoped credentials

On a Linux host with unprivileged namespaces and Landlock ABI revision three or newer, `lia wrap`
can put the wrapped process behind a user/mount/network/PID/UTS/IPC namespace boundary. The helper
must be an explicitly digest-pinned, root-owned `unshare` binary:

```bash
lia wrap --repo ./repo --evidence-dir /safe/evidence --config gate-config.json \
  --secret-key-hex "$LIA_SECRET" --linux-confine \
  --unshare-bin /usr/bin/unshare --expected-unshare-sha256 <sha256> \
  -- agent-command
```

The child cannot start until the trusted inner wrapper reports distinct namespace identities,
installs a read-only evidence mount, applies a Landlock write allow-rule only to the worktree, drops
capabilities, and waits for a parent `GO`. The parent then writes signed confinement evidence and
binds it into the process-completion manifest. A fresh network namespace with no external interface
blocks IP egress for that wrapped process. Unsupported hosts, helper drift, failed mounts, or a
missing Landlock boundary stop before the agent runs.

Credentials are optional, one-shot, and deadline-bounded:

```bash
chmod 600 /safe/credentials/api-token
lia wrap ... --linux-confine ... \
  --credential api=/safe/credentials/api-token --credential-ttl-seconds 30 \
  -- agent-command
# inside that wrapped process only:
lia credential-read --name api
```

The secret comes from a private, current-owner, single-link regular file; it is delivered over an
inherited file descriptor, never placed in the environment, and its exact source path is masked in
the child mount namespace. Broker memory must be locked or setup fails; it is overwritten and
unlocked after the sole request, and a late or repeated request fails.

This is scoped CONFINE for IP egress and filesystem-path writes outside the worktree, not complete
mediation or a separate-principal sandbox. Reads outside the worktree, pre-opened descriptors,
pathname Unix sockets (this backend does not install Landlock network/IPC rights), and another
process running as the operator remain residual risks. Hook/MCP adapters do not inherit this
assurance automatically.

Long journals can be rotated without discarding the full archive, and a compact signed head/tail
manifest can be verified separately:

```bash
lia journal-maintain --db journal.db --archive-dir journal-archive \
  --max-rows 100000 --max-bytes 268435456 --max-age-seconds 86400 \
  --secret-key-hex "$LIA_SECRET"
lia journal-anchors --db journal.db --head 2 --tail 2 \
  --secret-key-hex "$LIA_SECRET" --out anchors.json
lia journal-anchors-verify anchors.json --expected-public-key-hex "$LIA_PUBLIC_KEY"
lia journal-verify archived-journal.db --immutable
```

Rotation keeps the old database verifiable and starts the active database with a signed bridge to
the prior head. The anchor manifest authenticates retained hashes; it is not a replacement for the
omitted middle evidence. Maintenance fails closed on a busy/corrupt journal. TerminusLia performs
the same threshold check automatically; `LIA_JOURNAL_MAX_ROWS`, `LIA_JOURNAL_MAX_BYTES`, and
`LIA_JOURNAL_MAX_AGE_SECONDS` override its defaults. Normal verification participates in the live
journal lifecycle lock. `--immutable` is only for a stable offline archive/copy; it creates no
adjacent lock database and refuses WAL, SHM, or rollback-journal sidecars that immutable SQLite
would otherwise ignore.

## What is measured

See `docs/claims.json` — every number in public docs must carry a `[MEASURED]`
or `[EXTERNAL]` tag and pass `lia claims-lint`.

| Lane | What it proves | Status |
|------|----------------|--------|
| Trust three-arm (Harbor) | PREVENT catch on adversarial corpus | MEASURED (see claims) |
| Generic live tool-loop | Full gate set + ground + syco | MEASURED (separate from Harbor utility) |
| Claude Code adapter path | PREVENT OFF/ON on frozen corpus via real hook | MEASURED recorded-adapter (see claims); live separate |
| Codex adapter path | PREVENT OFF/ON on frozen corpus via real MCP | MEASURED recorded-adapter (see claims); live separate |
| Gemini/Cursor adapter paths | Native payload/config conformance + signed deny through installed wrappers | MEASURED local fixtures only; live harness agents unmeasured |
| Process/public/registry M4 | Contract/manifest negatives, pinned-helper delegation, cache/timeout controls | MEASURED local fixtures only; no public-log or live-registry claim |
| Linux confinement M5 | Namespaces, IP/path-write deny, durable signed report, scoped credential lifecycle | MEASURED local production fixtures only; no read/Unix-socket/same-principal or cloud-agent claim |
| TerminusLia TB2/Claw | Shell-irreversible only (livability companion) | MEASURED companion — **not** full trust stack |
| Recorded cassette | Offline when live unreachable | MEASURED, never pooled with live |

## Assurance honesty

Adapter capability cells live in `bench/assurance_truth.json` and must be
probe-derived where possible (`bench/probe_assurance.sh`). Ordinary generic wrap is not CONFINE;
only a successful per-run `--linux-confine` attestation earns its narrow IP/path-write cells.
Claude Code, Codex, Gemini CLI, and Cursor install surfaces are **GATE** only for their mapped tool
paths. TerminusLia is
GATE for shell only; ground/syco/ast are CANNOT-OBSERVE on that path.

## Useful without commercial harness

LIA Trust is the open, model-neutral safety and verification kernel. LIA is
the complete autonomous engineering system built on it. The Kernel runs as a
standalone `lia` binary: install hooks/MCP, gate actions, journal receipts,
offline verify. No commercial LIA Harness/Canvas required.

## Do not claim

- Grounding helped TB2/Claw until it is on the Terminus path.
- Complete mediation / CONFINE for Claude Code, Codex, or ordinary generic wrap.
- Pooled recorded + live catch rates.
- Utility pass-rate as the product metric.
