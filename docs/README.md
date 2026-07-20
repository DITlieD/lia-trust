# LIA Trust Kernel

Fail-closed trust gates for agent actions: journaled decisions, policy-as-data,
and offline verify. Product metric is **TRUST-INTEGRITY** (catch / residual /
false-block on the trust corpus), not utility pass-rate.

**Kernel** (this repo) is the installable TCB: protocol + journal + Ed25519
receipts + seven gates + offline verify + thin adapters. It is **not** the
commercial Harness / Canvas product layers.

## One-line install (recommended)

From a **clone** of this repo:

```bash
bash install.sh
```

Classic **curl | bash** style (after the repo is public / raw URL works):

```bash
curl -fsSL https://raw.githubusercontent.com/lia-trust/lia-trust/main/install.sh | bash
```

That script will:

1. Build `lia` (or reuse `target/release/lia` if present)
2. Install the binary to `~/.local/bin/lia`
3. Wire **Claude Code** + **Codex** with `lia install --apply-live`

### Installer knobs (env)

| Env | Effect |
|-----|--------|
| `LIA_NO_WIRE=1` | Binary only — do not touch `~/.claude` / `~/.codex` |
| `LIA_DRY_RUN=1` | Plan harness merge only |
| `LIA_PREFIX=~/.local` | Install prefix (`bin/lia`) |
| `LIA_FORCE_BUILD=1` | Always rebuild |

Examples:

```bash
# binary only
LIA_NO_WIRE=1 bash install.sh

# dry-run harness wiring
LIA_DRY_RUN=1 bash install.sh
```

### After install

```bash
lia status
# claude_hook_installed: true
# codex_mcp_installed: true
# assurance: GATE … never CONFINE

lia journal-verify ~/.lia-trust/journal/default.db
lia uninstall --apply-live    # remove wiring; keeps journal/keys
```

### Manual (no install.sh)

```bash
cargo build -p lia-cli --release
./target/release/lia install --apply-live
```

What install does:

| Target | Wiring |
|--------|--------|
| Claude Code | `~/.claude/settings.json` → PreToolUse hook → `lia hook` |
| Codex | `~/.codex/config.toml` → `[mcp_servers.lia-trust]` → `lia mcp` |
| State | `~/.lia-trust/` keys, journal, policy, wrappers |

Enforced only where hooks/MCP fire (**GATE**). Not complete mediation; not CONFINE.

See `docs/CONTRACTS.md`, `docs/harness-compatibility.md`, `docs/threat-model.md`.

## What is measured

See `docs/claims.json` — every number in public docs must carry a `[MEASURED]`
or `[EXTERNAL]` tag and pass `lia claims-lint`.

| Lane | What it proves | Status |
|------|----------------|--------|
| Trust three-arm (Harbor) | PREVENT catch on adversarial corpus | MEASURED (see claims) |
| Generic live tool-loop | Full gate set + ground + syco | MEASURED (separate from Harbor utility) |
| Claude Code adapter path | PREVENT OFF/ON on frozen corpus via real hook | MEASURED recorded-adapter (see claims); live separate |
| Codex adapter path | PREVENT OFF/ON on frozen corpus via real MCP | MEASURED recorded-adapter (see claims); live separate |
| TerminusLia TB2/Claw | Shell-irreversible only (livability companion) | MEASURED companion — **not** full trust stack |
| Recorded cassette | Offline when live unreachable | MEASURED, never pooled with live |

## Assurance honesty

Adapter capability cells live in `bench/assurance_truth.json` and must be
probe-derived where possible (`bench/probe_assurance.sh`). Generic wrap is not
CONFINE in v1. Claude Code / Codex install surface is **GATE**. TerminusLia is
GATE for shell only; ground/syco/ast are CANNOT-OBSERVE on that path.

## Useful without commercial harness

LIA Trust Kernel runs as a standalone `lia` binary: install hooks/MCP, gate
actions, journal receipts, offline verify. No ELAI/Harness/Canvas required.

## Do not claim

- Grounding helped TB2/Claw until it is on the Terminus path.
- Complete mediation / CONFINE for Claude Code, Codex, or generic wrap in v1.
- Pooled recorded + live catch rates.
- Utility pass-rate as the product metric.
