import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bench.harbor.lia_decision import (
    DenyMemo,
    GateMetrics,
    fail_closed,
    journal_verification_decision,
    parse_gate_response,
    validate_receipt_head,
)


def response(verdict: str, reason: str = "SHELL_ALLOW", receipts: bool = True) -> str:
    return json.dumps(
        {
            "outcomes": [
                {
                    "verdict": verdict,
                    "reason_code": reason,
                    "detail": "fixture",
                }
            ],
            "overall": verdict,
            "journal_receipts": [{"seq": 1, "row_hash": "a" * 64}]
            if receipts
            else [],
        }
    )


class LiaDecisionTests(unittest.TestCase):
    def test_missing_binary_is_stable_fail_closed(self) -> None:
        decision = fail_closed("LIA_GATE_UNAVAILABLE", "binary missing")
        self.assertTrue(decision["deny"])
        self.assertEqual(decision["reason_code"], "LIA_GATE_UNAVAILABLE")

    def test_empty_and_malformed_output_fail_closed(self) -> None:
        self.assertEqual(
            parse_gate_response("", 0, "empty")["reason_code"],
            "LIA_GATE_EMPTY_OUTPUT",
        )
        self.assertEqual(
            parse_gate_response("not-json", 0, "")["reason_code"],
            "LIA_GATE_BAD_JSON",
        )

    def test_missing_outcome_and_receipt_fail_closed(self) -> None:
        self.assertEqual(
            parse_gate_response(json.dumps({"outcomes": []}), 0, "")["reason_code"],
            "LIA_GATE_MISSING_VERDICT",
        )
        self.assertEqual(
            parse_gate_response(response("allow", receipts=False), 0, "")[
                "reason_code"
            ],
            "LIA_JOURNAL_RECEIPT_MISSING",
        )

    def test_only_verified_allow_shape_can_allow(self) -> None:
        allowed = parse_gate_response(response("allow"), 0, "")
        self.assertFalse(allowed["deny"])
        self.assertEqual(allowed["reason_code"], "SHELL_ALLOW")

    def test_incomplete_unknown_and_deny_are_blocking(self) -> None:
        incomplete = parse_gate_response(
            response("incomplete", "EVIDENCE_INCOMPLETE"), 2, ""
        )
        self.assertTrue(incomplete["deny"])
        self.assertEqual(incomplete["reason_code"], "EVIDENCE_INCOMPLETE")

        unknown = parse_gate_response(response("mystery", "UNKNOWN"), 0, "")
        self.assertTrue(unknown["deny"])
        self.assertEqual(unknown["reason_code"], "LIA_GATE_UNKNOWN_VERDICT")

        denied = parse_gate_response(response("deny", "SHELL_DESTRUCTIVE"), 2, "")
        self.assertTrue(denied["deny"])
        self.assertEqual(denied["reason_code"], "SHELL_DESTRUCTIVE")

    def test_journal_verification_failure_is_blocking(self) -> None:
        self.assertFalse(journal_verification_decision(0, "ok", "")["deny"])
        failed = journal_verification_decision(1, "", "tamper")
        self.assertTrue(failed["deny"])
        self.assertEqual(failed["reason_code"], "LIA_JOURNAL_VERIFY_FAILED")

    def test_receipt_must_match_verified_journal_head(self) -> None:
        decision = parse_gate_response(response("allow"), 0, "")
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "journal.db"
            connection = sqlite3.connect(db)
            connection.execute(
                "CREATE TABLE journal_rows (seq INTEGER PRIMARY KEY, row_hash TEXT NOT NULL)"
            )
            connection.execute(
                "INSERT INTO journal_rows(seq, row_hash) VALUES(1, ?)", ("a" * 64,)
            )
            connection.commit()
            connection.close()
            self.assertFalse(validate_receipt_head(decision, db)["deny"])

            stale = dict(decision)
            stale["receipt_row_hash"] = "b" * 64
            mismatch = validate_receipt_head(stale, db)
            self.assertTrue(mismatch["deny"])
            self.assertEqual(mismatch["reason_code"], "LIA_RECEIPT_HEAD_MISMATCH")

    def test_deny_memo_is_ttl_context_bound_and_never_caches_allow(self) -> None:
        memo = DenyMemo(ttl_seconds=5.0, max_entries=2)
        denied = {"deny": True, "reason_code": "SHELL_DESTRUCTIVE"}
        allowed = {"deny": False, "reason_code": "SHELL_ALLOW"}
        with patch("bench.harbor.lia_decision.time.monotonic", return_value=10.0):
            memo.put("rm -rf /", "ctx-a", denied)
            memo.put("echo ok", "ctx-a", allowed)
            self.assertEqual(memo.get("rm -rf /", "ctx-a"), denied)
            self.assertIsNone(memo.get("echo ok", "ctx-a"))
            self.assertIsNone(memo.get("rm -rf /", "ctx-b"))
        with patch("bench.harbor.lia_decision.time.monotonic", return_value=16.0):
            self.assertIsNone(memo.get("rm -rf /", "ctx-a"))

    def test_gate_metrics_are_bounded_and_machine_readable(self) -> None:
        metrics = GateMetrics(max_samples=3)
        metrics.record_spawn(10.0, "SHELL_ALLOW")
        metrics.record_spawn(20.0, "SHELL_DESTRUCTIVE")
        metrics.record_spawn(30.0, "LIA_GATE_TIMEOUT")
        metrics.record_spawn(40.0, "SHELL_OUT_OF_SCOPE")
        metrics.record_memo_hit()
        snapshot = metrics.snapshot()
        self.assertEqual(snapshot["gate_spawns"], 4)
        self.assertEqual(snapshot["memo_hits"], 1)
        self.assertEqual(snapshot["latency_sample_count"], 3)
        self.assertEqual(snapshot["timeout_count"], 1)
        self.assertEqual(snapshot["reason_counts"]["SHELL_DESTRUCTIVE"], 1)
        self.assertEqual(snapshot["mean_gate_latency_ms"], 30.0)


if __name__ == "__main__":
    unittest.main()
