# Assurance matrix (v1 honesty)

Source of truth for published cells: `bench/assurance_truth.json`.
Regenerate from probes via `bench/probe_assurance.sh` when adapters change.

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
| claude-code | GATE | PREVENT | PREVENT (tool path) | Harbor utility unmeasured |
| codex | GATE | PREVENT | PREVENT (tool path) | Harbor utility unmeasured |
| generic | OBSERVE | CANNOT-OBSERVE | DETECT | Not complete mediation |
| terminus-lia | GATE (shell only) | PREVENT | CANNOT-OBSERVE | TB2/Claw path; not full stack |

## Drift rule

Never pool TerminusLia shell-only metrics with generic live-tool-loop
TRUST-INTEGRITY. Never hard-code overclaim: if a gate is not on the path, the
cell is CANNOT-OBSERVE.
