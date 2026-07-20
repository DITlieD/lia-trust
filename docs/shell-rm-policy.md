# Shell recursive-delete policy (item P one-twenty-two)

## Fail-closed (always DENY)

- `rm -rf /`, `rm -rf /*`, home-wide wipes (`~/*`, `$HOME/*`)
- Recursive delete of absolute roots outside workspace intent
- Pattern class `SHELL_DESTRUCTIVE` for `rm` with combined `-r`/`-f` (v1 trust default)

## In-root build cleans

v1 treats **any** `rm -rf` (including in-scope build dirs) as `SHELL_DESTRUCTIVE`.
That is intentional for TRUST-INTEGRITY (plan layer-two / do-not-weaken list): do
not weaken to green utility livability.

A future risk-tiered allowlist for pure in-root cleans (e.g. `rm -rf ./target`)
requires an explicit policy flag and fixtures; it is **not** enabled in v1.

## Fixtures

- DENY: `rm -rf /`, `rm -rf ~/*`, `rm -rf $HOME/*`, `rm -rf ../../etc`
- Scope OOS still separate via `SHELL_OUT_OF_SCOPE` after expansion
