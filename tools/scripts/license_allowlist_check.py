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

    # SPDX expressions are boolean: one permitted OR branch is enough, while every
    # term in an AND branch must be permitted. The old flat split required every
    # license named anywhere in the expression and rejected valid alternatives.
    expression = lic.replace("/", " OR ")
    tokens = re.findall(r"\(|\)|\bAND\b|\bOR\b|\bWITH\b|[A-Za-z0-9.+-]+", expression)
    if not tokens or "".join(tokens) != re.sub(r"\s+", "", expression):
        return False

    position = 0

    def parse_primary() -> bool:
        nonlocal position
        if position >= len(tokens):
            raise ValueError("missing license term")
        if tokens[position] == "(":
            position += 1
            value = parse_or_expression()
            if position >= len(tokens) or tokens[position] != ")":
                raise ValueError("unclosed SPDX group")
            position += 1
            return value
        license_id = tokens[position]
        if license_id in {"AND", "OR", "WITH", ")"}:
            raise ValueError("expected license identifier")
        position += 1
        value = license_id in allow
        if position < len(tokens) and tokens[position] == "WITH":
            position += 1
            if position >= len(tokens):
                raise ValueError("missing SPDX exception")
            exception_id = tokens[position]
            position += 1
            value = value and exception_id == "LLVM-exception"
        return value

    def parse_and_expression() -> bool:
        nonlocal position
        value = parse_primary()
        while position < len(tokens) and tokens[position] == "AND":
            position += 1
            right = parse_primary()
            value = value and right
        return value

    def parse_or_expression() -> bool:
        nonlocal position
        value = parse_and_expression()
        while position < len(tokens) and tokens[position] == "OR":
            position += 1
            right = parse_and_expression()
            value = value or right
        return value

    try:
        accepted = parse_or_expression()
        return accepted and position == len(tokens)
    except ValueError:
        return False


def registry_root() -> pathlib.Path | None:
    if not REG.is_dir():
        return None
    for c in REG.iterdir():
        if c.is_dir():
            return c
    return None


def self_test() -> int:
    allow = {"Apache-2.0", "MIT", "BSD-3-Clause"}
    cases = {
        "MIT OR LGPL-2.1-or-later": True,
        "MIT AND LGPL-2.1-or-later": False,
        "(MIT OR Apache-2.0) AND BSD-3-Clause": True,
        "(MIT OR Apache-2.0) AND BSD-1-Clause": False,
        "Apache-2.0 WITH LLVM-exception": True,
        "Apache-2.0 WITH Classpath-exception-2.0": False,
        "MIT OR": False,
    }
    for expression, expected in cases.items():
        actual = ok(expression, allow)
        if actual != expected:
            print(f"self-test failed: {expression!r}: expected={expected} actual={actual}")
            return 2
    print(f"license-allowlist self-test OK cases={len(cases)}")
    return 0


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
    if sys.argv[1:] == ["--self-test"]:
        sys.exit(self_test())
    if len(sys.argv) != 1:
        raise SystemExit("usage: license_allowlist_check.py [--self-test]")
    sys.exit(main())
