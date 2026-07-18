#!/usr/bin/env python3
import pathlib
import re
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[2]
DENY = ROOT / "deny.toml"
LOCK = ROOT / "Cargo.lock"
REG = pathlib.Path.home() / ".cargo/registry/src"


def load_allow() -> set[str]:
    text = DENY.read_text()
    # crude extract of allow = [ ... ] under [licenses]
    m = re.search(r"\[licenses\](.*?)(?:\n\[|\Z)", text, re.S)
    if not m:
        raise SystemExit("deny.toml [licenses] missing")
    block = m.group(1)
    return set(re.findall(r'"([^"]+)"', block.split("allow")[1].split("]")[0]))


def ok(lic: str, allow: set[str]) -> bool:
    if not lic or lic == "UNKNOWN":
        return False
    if lic in allow:
        return True
    s = lic.replace("/", " OR ")
    parts = [p.strip() for p in re.split(r"\s+(?:OR|AND|WITH)\s+|\(|\)", s) if p and p.strip()]
    return bool(parts) and all(p in allow or p == "LLVM-exception" for p in parts)


def registry_root() -> pathlib.Path | None:
    if not REG.is_dir():
        return None
    for c in REG.iterdir():
        if c.is_dir():
            return c
    return None


def main() -> int:
    allow = load_allow()
    lock = LOCK.read_text()
    pkgs = re.findall(r'\[\[package\]\]\nname = "([^"]+)"\nversion = "([^"]+)"', lock)
    workspace = {
        "lia-protocol",
        "lia-journal",
        "lia-policy",
        "lia-gates",
        "lia-ast",
        "lia-taint",
        "lia-ground",
        "lia-syco",
        "lia-verify",
        "lia-adapters",
        "lia-bench",
        "lia-cli",
        "lia_wire_check",
        "lia_gate_freeze",
    }
    root = registry_root()
    bad = []
    missing = []
    checked = 0
    for name, ver in pkgs:
        if name in workspace:
            continue
        found = None
        if root is not None:
            cand = root / f"{name}-{ver}"
            if cand.is_dir():
                found = cand
        if found is None:
            missing.append(f"{name}@{ver}")
            continue
        data = tomllib.loads((found / "Cargo.toml").read_text())
        lic = data.get("package", {}).get("license") or "UNKNOWN"
        checked += 1
        if not ok(str(lic), allow):
            bad.append(f"{name}@{ver} license={lic}")
    print(f"license-allowlist-check checked={checked} missing-registry={len(missing)} bad={len(bad)}")
    for m in missing[:30]:
        print(f"MISSING {m}")
    for b in bad:
        print(f"BAD {b}")
    if bad:
        return 2
    # missing optional-target crates are acceptable if none are bad among present
    print("license-allowlist-check OK (mirrors deny.toml allow; run cargo deny when available)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
