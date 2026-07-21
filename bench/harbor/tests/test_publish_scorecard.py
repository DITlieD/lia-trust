import unittest

from bench.harbor.scripts.publish_scorecard import (
    GATE_METRICS_MARKER,
    marker_objects,
    summarize_gate_snapshots,
)


class PublishScorecardTests(unittest.TestCase):
    def test_nested_trajectory_marker_decodes_structured_metrics(self) -> None:
        trajectory = {
            "messages": [
                {
                    "content": (
                        "ok\n"
                        + GATE_METRICS_MARKER
                        + '{"gate_spawns":2,"memo_hits":1,"reason_counts":{"SHELL_DESTRUCTIVE":2}}'
                    )
                }
            ]
        }
        found = list(marker_objects(trajectory, GATE_METRICS_MARKER))
        self.assertEqual(found[0]["memo_hits"], 1)
        self.assertEqual(found[0]["reason_counts"]["SHELL_DESTRUCTIVE"], 2)

    def test_gate_metrics_aggregate_trials_without_pooling_cumulative_snapshots(self) -> None:
        summary = summarize_gate_snapshots(
            [
                {
                    "gate_spawns": 2,
                    "memo_hits": 1,
                    "timeout_count": 0,
                    "latency_sample_count": 2,
                    "mean_gate_latency_ms": 10,
                    "memo_size": 1,
                    "reason_counts": {"SHELL_DESTRUCTIVE": 2},
                },
                {
                    "gate_spawns": 1,
                    "memo_hits": 3,
                    "timeout_count": 1,
                    "latency_sample_count": 1,
                    "mean_gate_latency_ms": 40,
                    "memo_size": 2,
                    "reason_counts": {"LIA_GATE_TIMEOUT": 1},
                },
            ]
        )
        self.assertEqual(summary["status"], "MEASURED")
        self.assertEqual(summary["gate_spawns"], 3)
        self.assertEqual(summary["memo_hits"], 4)
        self.assertEqual(summary["timeout_count"], 1)
        self.assertEqual(summary["mean_gate_latency_ms"], 20.0)
        self.assertEqual(summary["memo_size_max"], 2)


if __name__ == "__main__":
    unittest.main()
