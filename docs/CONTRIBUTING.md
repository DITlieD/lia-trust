# Contributing to LIA Trust Kernel

## Ground rules

1. **Fail-closed** — new gates default deny on missing evidence.
2. **No stub gates** — no `.unwrap()` on production paths; no placeholder bodies.
3. **Honest claims** — every public number needs a `[MEASURED]` or `[EXTERNAL]`
   tag and a recompute pointer; run `lia claims-lint docs/`.
4. **Adapter honesty** — never claim PREVENT/CONFINE without a probe-backed cell.
5. **Tests drive shipped entrypoints** — unit tests may call library APIs that the
   CLI uses; do not reimplement gates inside tests.

## Dev loop

```bash
cargo test --workspace
cargo build -p lia-cli --release
./target/release/lia claims-lint docs/
./conformance/run.sh
./tools/scripts/is2_smoke.sh
```

Install kernel into a **fixture** home (never silently rewrite live configs):

```bash
./target/release/lia install \
  --lia-home /tmp/lia-fixture/home \
  --claude-home /tmp/lia-fixture/claude \
  --codex-home /tmp/lia-fixture/codex \
  --lia-bin "$PWD/target/release/lia"
```

## PR expectations

- Update `docs/LIA-TRUST-KERNEL-PLAN-MISSING.md` when closing a plan unit.
- Add fixtures for new landmine classes under `bench/gate_fixtures` / corpus.
- Keep `contracts.json` + `docs/CONTRACTS.md` in sync when field names change.

## Code of conduct

See `docs/CODE_OF_CONDUCT.md`.
