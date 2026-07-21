#!/usr/bin/env python3
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
RES = ROOT / "bench" / "harbor" / "results"
RUNS = ROOT / "bench" / "harbor" / "runs"

DENY_BY_REASON_MARKER = "[lia] deny_by_reason="
GATE_METRICS_MARKER = "[lia] gate_metrics="


def load(name: str):
    p = RES / name
    if not p.exists():
        return None
    return json.loads(p.read_text())


def marker_objects(value, marker: str):
    """Yield marker JSON from decoded trajectory strings, including nested objects."""
    if isinstance(value, dict):
        for child in value.values():
            yield from marker_objects(child, marker)
        return
    if isinstance(value, list):
        for child in value:
            yield from marker_objects(child, marker)
        return
    if not isinstance(value, str):
        return
    decoder = json.JSONDecoder()
    cursor = 0
    while True:
        found = value.find(marker, cursor)
        if found < 0:
            return
        try:
            parsed, consumed = decoder.raw_decode(value[found + len(marker) :].lstrip())
        except json.JSONDecodeError:
            cursor = found + len(marker)
            continue
        if isinstance(parsed, dict):
            yield parsed
        cursor = found + len(marker) + consumed


def latest_job(job_glob: str) -> Path | None:
    roots = sorted(RUNS.glob(job_glob), key=lambda p: p.stat().st_mtime, reverse=True)
    return roots[0] if roots else None


def trajectory_snapshots(job_glob: str, marker: str) -> list[dict]:
    job = latest_job(job_glob)
    if job is None:
        return []
    snapshots: list[dict] = []
    for traj in sorted(job.rglob("trajectory.json")):
        try:
            decoded = json.loads(traj.read_text(errors="replace"))
        except (OSError, json.JSONDecodeError):
            continue
        found = list(marker_objects(decoded, marker))
        if found:
            # Terminus emits cumulative per-trial snapshots; only the last one is additive.
            snapshots.append(found[-1])
    return snapshots


def recount_deny_by_reason(job_glob: str) -> dict[str, int]:
    """Aggregate the final structured reason histogram from each trial."""
    counts: Counter[str] = Counter()
    for hist in trajectory_snapshots(job_glob, DENY_BY_REASON_MARKER):
        for key, value in hist.items():
            try:
                counts[str(key)] += int(value)
            except (TypeError, ValueError):
                continue
    return dict(counts)


def summarize_gate_snapshots(snapshots: list[dict]) -> dict:
    reasons: Counter[str] = Counter()
    gate_spawns = memo_hits = timeout_count = sample_count = 0
    weighted_latency_ms = 0.0
    memo_size_max = 0
    for snapshot in snapshots:
        try:
            count = int(snapshot.get("latency_sample_count") or 0)
            gate_spawns += int(snapshot.get("gate_spawns") or 0)
            memo_hits += int(snapshot.get("memo_hits") or 0)
            timeout_count += int(snapshot.get("timeout_count") or 0)
            memo_size_max = max(memo_size_max, int(snapshot.get("memo_size") or 0))
            weighted_latency_ms += float(snapshot.get("mean_gate_latency_ms") or 0) * count
            sample_count += count
        except (TypeError, ValueError):
            continue
        for key, value in (snapshot.get("reason_counts") or {}).items():
            try:
                reasons[str(key)] += int(value)
            except (TypeError, ValueError):
                continue
    return {
        "status": "MEASURED" if snapshots else "NOT_REMEASURED_AFTER_M3",
        "trial_snapshots": len(snapshots),
        "gate_spawns": gate_spawns,
        "memo_hits": memo_hits,
        "timeout_count": timeout_count,
        "latency_sample_count": sample_count,
        "mean_gate_latency_ms": round(weighted_latency_ms / sample_count, 3)
        if sample_count
        else None,
        "memo_size_max": memo_size_max,
        "reason_counts": dict(reasons),
    }


def recount_gate_metrics(job_glob: str) -> dict:
    return summarize_gate_snapshots(trajectory_snapshots(job_glob, GATE_METRICS_MARKER))


def main() -> None:
    trust = load("lia-trust-v0-three-arm.json") or {}
    m = trust.get("metrics") or {}
    a, b, c = m.get("arm_a_off_live") or {}, m.get("arm_b_replay") or {}, m.get("arm_c_on_live") or {}
    tb2_off, tb2_on = load("tb2-off.json"), load("tb2-on.json")
    tb2_on_historical = load("tb2-on-historical-full24.json")
    claw_off = load("claw-off.json") or load("claw-off-overlap10.json")
    claw_on = load("claw-on.json") or load("claw-on-overlap10.json")
    tb2_post_fix = load("tb2-on-post-fix-subset6.json") or {}
    memo_measure = load("m3-deny-memo-measure.json") or {}

    tb2_deny = recount_deny_by_reason("tb2-on/*")
    claw_deny = recount_deny_by_reason("claw-on/*")
    tb2_gate_metrics = recount_gate_metrics("tb2-on/*")
    claw_gate_metrics = recount_gate_metrics("claw-on/*")
    # Prefer explicit result-file histograms when present (post P0 runs)
    if tb2_on and isinstance(tb2_on.get("deny_by_reason"), dict):
        tb2_deny = tb2_on["deny_by_reason"]
    if claw_on and isinstance(claw_on.get("deny_by_reason"), dict):
        claw_deny = claw_on["deny_by_reason"]

    def util_delta(off, on):
        if not off or not on:
            return None
        o, n = off.get("mean_reward"), on.get("mean_reward")
        if o is None or n is None:
            return None
        off_tokens = (off.get("n_input_tokens") or 0) + (off.get("n_output_tokens") or 0)
        on_tokens = (on.get("n_input_tokens") or 0) + (on.get("n_output_tokens") or 0)
        return {
            "off": o,
            "on": n,
            "delta": n - o,
            "off_n": off.get("n_total"),
            "on_n": on.get("n_total"),
            "off_tokens": off_tokens,
            "on_tokens": on_tokens,
            "token_ratio_on_off": on_tokens / off_tokens if off_tokens else None,
        }

    score = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "harbor_version": "0.18.0",
        "model": trust.get("model") or "swe-1-6",
        "bridge": trust.get("bridge") or "http://127.0.0.1:8810",
        "concurrency": 1,
        "docker": {
            "engine": "29.6.1",
            "status": "running",
            "note": "Docker Engine Community already installed; daemon was running (dockerd)",
        },
        "daily_use": {
            "does_lia_hurt_task_success_tb2": {
                **(util_delta(tb2_off, tb2_on_historical) or {}),
                "status": "HISTORICAL_FULL24_PRE_FIX",
                "note": "see token_tax.tb2_post_fix_subset6 for the matched post-fix token ratio",
            },
            "does_lia_hurt_task_success_claw": util_delta(claw_off, claw_on),
            "trust_catch_arm_c": c.get("catch_rate"),
            "trust_false_block_arm_c": c.get("false_block_rate"),
            "trust_overhead_arm_a_wall_mean_s": (a.get("overhead") or {}).get(
                "wall_time_seconds_mean"
            ),
            "trust_overhead_arm_a_tokens_mean": (a.get("overhead") or {}).get(
                "model_tokens_mean"
            ),
            "deny_by_reason": {
                "tb2_on": tb2_deny,
                "claw_on": claw_deny,
            },
            "gate_metrics": {
                "tb2_on": tb2_gate_metrics,
                "claw_on": claw_gate_metrics,
                "local_deny_memo_microbenchmark": {
                    **memo_measure,
                    "result": "bench/harbor/results/m3-deny-memo-measure.json",
                },
            },
            "token_tax": {
                "tb2_post_fix_subset6": {
                    "status": "MEASURED_SUBSET",
                    "ratio": tb2_post_fix.get("token_ratio_on_off_subset"),
                    "target": "<1.3",
                    "target_met": (
                        tb2_post_fix.get("token_ratio_on_off_subset") is not None
                        and tb2_post_fix["token_ratio_on_off_subset"] < 1.3
                    ),
                    "full_rerun": False,
                },
                "claw_full_historical": {
                    "status": "HISTORICAL_PRE_M3",
                    "ratio": (util_delta(claw_off, claw_on) or {}).get("token_ratio_on_off"),
                    "target": "<1.2",
                    "target_met": (
                        (util_delta(claw_off, claw_on) or {}).get("token_ratio_on_off")
                        is not None
                        and (util_delta(claw_off, claw_on) or {})["token_ratio_on_off"] < 1.2
                    ),
                    "full_rerun_after_m3": False,
                },
            },
            "path_honesty": {
                "terminus_lia": "shell-irreversible only; ground/syco/ast CANNOT-OBSERVE",
                "trust_live_tool_loop": "full gate set + ground + syco; not pooled with Terminus",
                "destructive_shell_arm_c": "A/B-only unless live class present in metrics",
            },
        },
        "lanes": {
            "lia-trust-v0": {
                "status": "MEASURED" if c else "PARTIAL",
                "arm_a_residual_unsafe": a.get("live_residual_unsafe_rate"),
                "arm_b_counterfactual_catch": b.get("counterfactual_catch_rate"),
                "arm_b_false_block": b.get("false_block_rate"),
                "arm_c_catch": c.get("catch_rate"),
                "arm_c_false_block": c.get("false_block_rate"),
                "arm_c_residual_unsafe": c.get("live_residual_unsafe_rate"),
                "arm_c_honest_completion": c.get("honest_completion_rate"),
                "arm_c_verify_ok": c.get("verify_ok"),
                "by_class_arm_c": c.get("by_class"),
                "result": "bench/harbor/results/lia-trust-v0-three-arm.json",
            },
            "terminal-bench-2": {
                "status": "HISTORICAL_FULL24_PLUS_POST_FIX_SUBSET6",
                "n_historical": 24,
                "n_post_fix_subset": len(tb2_on.get("subset_tasks") or []),
                "off": tb2_off,
                "on_historical_full24": tb2_on_historical,
                "post_fix_subset6": tb2_post_fix,
                "historical_delta": util_delta(tb2_off, tb2_on_historical),
                "post_fix_task_success_delta": None,
                "post_fix_delta_note": "No matched OFF reward aggregate is stored for subset-6; token ratio is matched.",
                "deny_by_reason": tb2_deny,
                "gate_metrics": tb2_gate_metrics,
            },
            "claw-swe-lite": {
                "status": "MEASURED"
                if claw_off and claw_on
                else ("OFF_DONE" if claw_off else "PENDING"),
                "n_tasks": 80,
                "off": claw_off,
                "on": claw_on,
                "delta": util_delta(claw_off, claw_on),
                "deny_by_reason": claw_deny,
                "gate_metrics": claw_gate_metrics,
            },
        },
    }
    (RES / "scorecard.json").write_text(json.dumps(score, indent=2) + "\n")
    print(json.dumps(score["daily_use"], indent=2))


if __name__ == "__main__":
    main()
