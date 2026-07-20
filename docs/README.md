# LIA Trust Kernel

Fail-closed trust gates for agent actions: journaled decisions, policy-as-data,
and offline verify. Product metric is **TRUST-INTEGRITY** (catch / residual /
false-block on the trust corpus), not utility pass-rate.

**Kernel** (this repo) is the installable TCB: protocol + journal + Ed25519
receipts + seven gates + offline verify + thin adapters. It is **not** the
commercial Harness / Canvas product layers.

## Five-minute quickstart

```bash
# 1. Build
cargo build -p lia-cli --release
LIA=./target/release/lia

# 2. Install into Claude Code + Codex (fixture-safe by default)
#    Real ~/.claude and ~/.codex need --apply-live
$LIA install --apply-live

# 3. Confirm
$LIA status
# claude_hook_installed: true
# codex_mcp_installed: true
# assurance: GATE … never CONFINE

# 4. Offline verify after a session
$LIA journal-verify ~/.lia-trust/journal/default.db

# 5. Remove wiring (keeps journal/keys)
$LIA uninstall --apply-live
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
