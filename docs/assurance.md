# Assurance matrix (v1 honesty)

Source of truth for published cells: `bench/assurance_truth.json`.
Regenerate from probes via `bench/probe_assurance.sh` when adapters change.
Install-generated probe files describe only a static capability shape and set every
gate cell to CANNOT-OBSERVE. Published PREVENT/DETECT cells require the runtime probe,
which exercises the production CLI boundary, requires a signed row, verifies the
journal, and confirms that a mutated row fails verification.

## Roll-up levels

| Level | Meaning |
|-------|---------|
| AUDIT | Post-hoc only |
| OBSERVE | Detect without prevent |
| GATE | Pre-block on exercised gates |
| CONFINE | Complete mediation — **not claimed in v1** |

## Adapter summary

| Adapter | Level | Shell | Ground/syco | Notes |
|---------|-------|-------|-------------|-------|
| claude-code | GATE | PREVENT | CANNOT-OBSERVE | PreToolUse has no test-result or completion-result channel |
| codex | GATE | PREVENT | PREVENT (explicit proxy tools) | Native Codex tools can bypass MCP; test execution is not observed |
| generic | OBSERVE | CANNOT-OBSERVE | CANNOT-OBSERVE | Final filesystem diff plus signed journal; not complete mediation |
| terminus-lia | GATE (shell only) | PREVENT | CANNOT-OBSERVE | TB2/Claw path; not full stack |

## Drift rule

Never pool TerminusLia shell-only metrics with generic live-tool-loop
TRUST-INTEGRITY. Never hard-code overclaim: if a gate is not on the path, the
cell is CANNOT-OBSERVE.

`run_test` arguments supplied to the Codex MCP proxy are claims, not
wrapper-observed process results. Therefore `test-integrity` remains
CANNOT-OBSERVE until the proxy itself owns process execution and captures the
exit status. The generic wrapper records the wrapped process exit and final
diff, but it cannot identify which subprocess was a test or gate a model's
completion claim, so those two core cells also remain CANNOT-OBSERVE.
