# Shell recursive-delete policy (V2 / item P1-22)

## Fail-closed (always DENY)

- `rm -rf /`, `rm -rf /*`, home-wide wipes (`~/*`, `$HOME/*`)
- Recursive delete of absolute roots outside workspace intent
- Recursive deletion through a home-relative target (`~`, `$HOME`, `${HOME}`)
- Deletion of an entire allowed root, even when listed in cleanup policy

## Explicit in-root build cleans

V2 permits only a single, top-level recursive-force `rm` whose normalized concrete
targets all exactly match an explicit `cleanup_policy.approved_targets` entry. The
model does not decide legitimacy. Missing, empty, unknown-version, relative-target,
or non-matching policy fails closed.

```json
{
  "allowed_roots": ["/work/repo"],
  "cwd": "/work/repo",
  "cleanup_policy": {
    "version": 1,
    "approved_targets": ["/work/repo/target"]
  }
}
```

With that config, `rm -rf ./target` returns `SHELL_CLEANUP_APPROVED`.
The following stable denials explain why a cleanup was refused:

- `SHELL_CLEANUP_APPROVAL_REQUIRED` — valid in-root target lacks an exact approval
- `SHELL_CLEANUP_OUT_OF_SCOPE` — normalized or symlink-resolved target escapes roots
- `SHELL_CLEANUP_PROTECTED_TARGET` — target is policy, evidence, hook, or verifier state
- `SHELL_CLEANUP_AMBIGUOUS` — glob, unknown environment reference, unsupported flag,
  nested/compound shell, symlink traversal, or unverifiable metadata

`SHELL_DESTRUCTIVE` remains the reason for root/home/allowed-root boundaries and
all other true irreversible classes. This is still pre-execution tool-boundary
validation, not atomic deletion or TOCTOU-safe confinement.

## Fixtures

- ALLOW: exact approved `rm -rf ./target`, normalized equivalent spellings, known
  environment target bound to the same path
- DENY: missing approval, mixed approved/unapproved targets, globs, nested/compound
  commands, unknown environment variables, symlinks, protected paths, traversal/OOS
- HARD DENY: `rm -rf /`, `rm -rf ~/*`, `rm -rf $HOME/*`, allowed-root deletion,
  command/process substitution, and all existing non-cleanup irreversible fixtures
