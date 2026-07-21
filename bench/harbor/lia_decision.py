"""Fail-closed parsing for the optional Harbor Terminus adapter.

This module deliberately has no Harbor dependency so protocol failures can be
unit-tested without installing the benchmark runtime.
"""

from __future__ import annotations

import json
import sqlite3
import time
from collections import Counter, OrderedDict, deque
from pathlib import Path
from typing import Any

ALLOW_VERDICTS = frozenset({"allow", "verified"})
BLOCKING_VERDICTS = frozenset(
    {"deny", "refuted", "quarantine", "unsupported", "incomplete"}
)


class DenyMemo:
    """Small, TTL-bound cache that can only retain fail-closed decisions."""

    def __init__(self, ttl_seconds: float = 30.0, max_entries: int = 256) -> None:
        self._ttl_seconds = max(0.0, float(ttl_seconds))
        self._max_entries = max(1, int(max_entries))
        self._entries: OrderedDict[tuple[str, str], tuple[float, dict[str, Any]]] = (
            OrderedDict()
        )

    def _purge_expired(self, now: float) -> None:
        expired = [key for key, (deadline, _) in self._entries.items() if deadline <= now]
        for key in expired:
            self._entries.pop(key, None)

    def get(self, command: str, context: str) -> dict[str, Any] | None:
        now = time.monotonic()
        self._purge_expired(now)
        key = (command, context)
        found = self._entries.get(key)
        if found is None:
            return None
        _, decision = found
        self._entries.move_to_end(key)
        return dict(decision)

    def put(self, command: str, context: str, decision: dict[str, Any]) -> None:
        if decision.get("deny") is not True or self._ttl_seconds <= 0:
            return
        now = time.monotonic()
        self._purge_expired(now)
        key = (command, context)
        self._entries[key] = (now + self._ttl_seconds, dict(decision))
        self._entries.move_to_end(key)
        while len(self._entries) > self._max_entries:
            self._entries.popitem(last=False)

    def __len__(self) -> int:
        self._purge_expired(time.monotonic())
        return len(self._entries)


class GateMetrics:
    """Bounded in-memory latency samples plus monotonic decision counters."""

    def __init__(self, max_samples: int = 256) -> None:
        self._latency_ms: deque[float] = deque(maxlen=max(1, int(max_samples)))
        self._reason_counts: Counter[str] = Counter()
        self._gate_spawns = 0
        self._memo_hits = 0
        self._timeout_count = 0

    def record_spawn(self, latency_ms: float, reason_code: str) -> None:
        reason = reason_code or "LIA_GATE_UNKNOWN"
        self._gate_spawns += 1
        self._latency_ms.append(max(0.0, float(latency_ms)))
        self._reason_counts[reason] += 1
        if "TIMEOUT" in reason:
            self._timeout_count += 1

    def record_memo_hit(self) -> None:
        self._memo_hits += 1

    def snapshot(self) -> dict[str, Any]:
        sample_count = len(self._latency_ms)
        mean = sum(self._latency_ms) / sample_count if sample_count else 0.0
        return {
            "gate_spawns": self._gate_spawns,
            "memo_hits": self._memo_hits,
            "latency_sample_count": sample_count,
            "mean_gate_latency_ms": round(mean, 3),
            "timeout_count": self._timeout_count,
            "reason_counts": dict(sorted(self._reason_counts.items())),
        }


def fail_closed(reason_code: str, detail: str) -> dict[str, Any]:
    return {
        "deny": True,
        "reason_code": reason_code,
        "detail": detail[:500],
        "verdicts": [],
    }


def parse_gate_response(stdout: str, returncode: int, stderr: str) -> dict[str, Any]:
    if not stdout.strip():
        return fail_closed("LIA_GATE_EMPTY_OUTPUT", stderr or "gate emitted no JSON")
    try:
        parsed = json.loads(stdout)
    except (json.JSONDecodeError, TypeError) as error:
        return fail_closed("LIA_GATE_BAD_JSON", str(error))
    if not isinstance(parsed, dict):
        return fail_closed("LIA_GATE_BAD_JSON", "gate response must be an object")

    outcomes = parsed.get("outcomes")
    if not isinstance(outcomes, list) or not outcomes:
        return fail_closed("LIA_GATE_MISSING_VERDICT", "outcomes must be non-empty")
    if not all(isinstance(outcome, dict) for outcome in outcomes):
        return fail_closed("LIA_GATE_MISSING_VERDICT", "outcome must be an object")

    receipts = parsed.get("journal_receipts")
    if not isinstance(receipts, list) or not receipts:
        return fail_closed(
            "LIA_JOURNAL_RECEIPT_MISSING", "gate returned no signed journal receipt"
        )
    receipt = receipts[-1]
    if (
        not isinstance(receipt, dict)
        or not isinstance(receipt.get("seq"), int)
        or not isinstance(receipt.get("row_hash"), str)
        or not receipt["row_hash"]
    ):
        return fail_closed(
            "LIA_JOURNAL_RECEIPT_INVALID", "last receipt lacks seq or row_hash"
        )

    verdicts: list[str] = []
    for outcome in outcomes:
        verdict = outcome.get("verdict")
        if not isinstance(verdict, str) or not verdict.strip():
            return fail_closed("LIA_GATE_MISSING_VERDICT", "outcome lacks verdict")
        verdicts.append(verdict.lower())
    overall = parsed.get("overall")
    if isinstance(overall, str):
        verdicts.append(overall.lower())

    unknown = [
        verdict
        for verdict in verdicts
        if verdict not in ALLOW_VERDICTS and verdict not in BLOCKING_VERDICTS
    ]
    if unknown:
        return fail_closed(
            "LIA_GATE_UNKNOWN_VERDICT", f"unknown verdicts: {', '.join(unknown)}"
        )

    reason_code = next(
        (
            str(outcome["reason_code"])
            for outcome in outcomes
            if outcome.get("reason_code")
        ),
        None,
    )
    detail = next(
        (str(outcome["detail"]) for outcome in outcomes if outcome.get("detail")),
        "",
    )
    if any(verdict in BLOCKING_VERDICTS for verdict in verdicts):
        return {
            "deny": True,
            "reason_code": reason_code or "LIA_GATE_BLOCKED",
            "detail": detail,
            "verdicts": verdicts,
            "receipt_seq": receipt["seq"],
            "receipt_row_hash": receipt["row_hash"],
        }
    if returncode != 0:
        return fail_closed(
            "LIA_GATE_PROCESS_FAILED",
            stderr or f"gate exited {returncode} despite allow verdict",
        )
    return {
        "deny": False,
        "reason_code": reason_code or "LIA_GATE_ALLOW",
        "detail": detail,
        "verdicts": verdicts,
        "receipt_seq": receipt["seq"],
        "receipt_row_hash": receipt["row_hash"],
    }


def journal_verification_decision(
    returncode: int, stdout: str, stderr: str
) -> dict[str, Any]:
    if returncode == 0:
        return {
            "deny": False,
            "reason_code": "LIA_JOURNAL_VERIFIED",
            "detail": stdout[:500],
            "verdicts": ["verified"],
        }
    return fail_closed(
        "LIA_JOURNAL_VERIFY_FAILED",
        stderr or stdout or f"journal verifier exited {returncode}",
    )


def validate_receipt_head(
    decision: dict[str, Any], journal_path: Path
) -> dict[str, Any]:
    receipt_seq = decision.get("receipt_seq")
    receipt_hash = decision.get("receipt_row_hash")
    if not isinstance(receipt_seq, int) or not isinstance(receipt_hash, str):
        return fail_closed(
            "LIA_JOURNAL_RECEIPT_INVALID", "decision lacks receipt head metadata"
        )
    try:
        uri = journal_path.resolve().as_uri() + "?mode=ro"
        connection = sqlite3.connect(uri, uri=True)
        try:
            row = connection.execute(
                "SELECT seq, row_hash FROM journal_rows ORDER BY seq DESC LIMIT 1"
            ).fetchone()
        finally:
            connection.close()
    except (OSError, sqlite3.Error, ValueError) as error:
        return fail_closed("LIA_JOURNAL_HEAD_UNAVAILABLE", str(error))
    if row != (receipt_seq, receipt_hash):
        return fail_closed(
            "LIA_RECEIPT_HEAD_MISMATCH",
            f"receipt ({receipt_seq}, {receipt_hash}) does not match journal head {row}",
        )
    return {
        "deny": False,
        "reason_code": "LIA_RECEIPT_HEAD_VERIFIED",
        "detail": f"journal head seq={receipt_seq}",
        "verdicts": ["verified"],
    }
