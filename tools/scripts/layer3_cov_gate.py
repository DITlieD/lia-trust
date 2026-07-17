#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def load_functions(path: Path) -> dict[str, int]:
    data = json.loads(path.read_text())
    out: dict[str, int] = {}
    for file_data in data.get("data", []):
        for fn in file_data.get("functions", []):
            name = fn.get("name")
            if not name:
                continue
            count = int(fn.get("count", 0))
            short = name.split("::")[-1] if "::" in name else name
            out[name] = max(out.get(name, 0), count)
            out[short] = max(out.get(short, 0), count)
    return out


def match_count(counts: dict[str, int], needle: str) -> int | None:
    if needle in counts:
        return counts[needle]
    hits = [c for n, c in counts.items() if needle in n]
    if not hits:
        return None
    return max(hits)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", required=True, type=Path)
    ap.add_argument("--require-hit", action="append", default=[])
    ap.add_argument("--require-zero", action="append", default=[])
    ap.add_argument("--settling", action="store_true")
    args = ap.parse_args()

    if not args.json.is_file():
        print(f"BLOCK: missing {args.json}", file=sys.stderr)
        return 1

    counts = load_functions(args.json)
    if not counts:
        print("BLOCK: empty functions[]", file=sys.stderr)
        return 1

    if args.settling and (not args.require_zero or not args.require_hit):
        print("BLOCK: settling needs --require-zero and --require-hit", file=sys.stderr)
        return 1

    rc = 0
    for sym in args.require_zero:
        c = match_count(counts, sym)
        if c is None:
            print(f"BLOCK: {sym!r} absent", file=sys.stderr)
            rc = 1
        elif c != 0:
            print(f"BLOCK: {sym!r} count={c} want 0", file=sys.stderr)
            rc = 1
        else:
            print(f"OK stub-zero {sym} count=0")

    for sym in args.require_hit:
        c = match_count(counts, sym)
        if c is None:
            print(f"BLOCK: {sym!r} absent", file=sys.stderr)
            rc = 1
        elif c == 0:
            print(f"BLOCK: {sym!r} count=0", file=sys.stderr)
            rc = 1
        else:
            print(f"OK wired-hit {sym} count={c}")

    return rc


if __name__ == "__main__":
    sys.exit(main())
