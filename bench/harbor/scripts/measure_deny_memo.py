#!/usr/bin/env python3
"""Local TCB microbenchmark for a real gate spawn versus verified-denial memo hits."""

from __future__ import annotations

import argparse
import json
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bench.harbor.lia_decision import (
    DenyMemo,
    journal_verification_decision,
    parse_gate_response,
    validate_receipt_head,
)


def checked_run(argv: list[str], timeout: float = 10.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lia-bin", type=Path, default=Path("target/debug/lia"))
    parser.add_argument("--memo-samples", type=int, default=10_000)
    args = parser.parse_args()
    binary = args.lia_bin.resolve()
    samples = max(100, args.memo_samples)

    with tempfile.TemporaryDirectory(prefix="lia-memo-measure-") as raw_temp:
        temp = Path(raw_temp)
        root = temp / "workspace"
        root.mkdir()
        journal = temp / "journal.db"
        config = temp / "config.json"
        request = temp / "request.json"
        config.write_text(
            json.dumps(
                {
                    "allowed_roots": [str(root)],
                    "home_dir": str(root / "home"),
                    "cwd": str(root),
                    "protected_paths": [],
                    "registry": {},
                    "env": {"HOME": str(root / "home"), "PWD": str(root)},
                }
            )
        )
        request.write_text(
            json.dumps(
                {
                    "gate_id": "shell-irreversible",
                    "action_id": "00000000-0000-4000-8000-000000000001",
                    "kind": "shell",
                    "payload": {"command": "rm -rf /"},
                }
            )
        )
        secret = secrets.token_hex(32)
        started = time.perf_counter()
        gate = checked_run(
            [
                str(binary),
                "gate",
                "--config",
                str(config),
                "--request",
                str(request),
                "--journal",
                str(journal),
                "--secret-key-hex",
                secret,
                "--key-id",
                "m3-local-measure",
            ]
        )
        decision = parse_gate_response(gate.stdout, gate.returncode, gate.stderr)
        verify = checked_run([str(binary), "journal-verify", str(journal)])
        verified = journal_verification_decision(
            verify.returncode, verify.stdout, verify.stderr
        )
        head = validate_receipt_head(decision, journal)
        gate_tcb_latency_ms = (time.perf_counter() - started) * 1000.0
        if not decision.get("deny") or verified.get("deny") or head.get("deny"):
            raise SystemExit("real gate denial did not produce a verified receipt-bound decision")

        memo = DenyMemo(ttl_seconds=30.0, max_entries=8)
        command = "rm -rf /"
        context = json.dumps({"allowed_roots": [str(root)], "cwd": str(root)}, sort_keys=True)
        memo.put(command, context, decision)
        memo_started = time.perf_counter()
        hits = 0
        for _ in range(samples):
            if memo.get(command, context) == decision:
                hits += 1
        memo_elapsed = time.perf_counter() - memo_started
        memo_hit_mean_us = memo_elapsed * 1_000_000.0 / samples
        if hits != samples or memo.get(command, context + "-changed") is not None:
            raise SystemExit("memo correctness check failed")

        report = {
            "schema": "lia-m3-deny-memo-measure-v1",
            "classification": "LOCAL_MICROBENCHMARK_NOT_HARBOR_UTILITY",
            "gate_path": "lia gate + lia journal-verify + receipt-head validation",
            "gate_tcb_latency_ms": round(gate_tcb_latency_ms, 3),
            "memo_samples": samples,
            "memo_hits": hits,
            "memo_hit_mean_us": round(memo_hit_mean_us, 3),
            "observed_speedup_ratio": round(
                gate_tcb_latency_ms * 1000.0 / memo_hit_mean_us, 3
            ),
            "correctness": {
                "verified_denial_only": True,
                "changed_context_miss": True,
                "allow_cache": False,
                "full_harbor_rerun": False,
            },
        }
        print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
