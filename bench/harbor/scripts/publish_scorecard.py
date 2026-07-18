#!/usr/bin/env python3
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
RES = ROOT / "bench" / "harbor" / "results"


def load(name: str):
    p = RES / name
    if not p.exists():
        return None
    return json.loads(p.read_text())


def main() -> None:
    trust = load("lia-trust-v0-three-arm.json") or {}
    m = trust.get("metrics") or {}
    a, b, c = m.get("arm_a_off_live") or {}, m.get("arm_b_replay") or {}, m.get("arm_c_on_live") or {}
    tb2_off, tb2_on = load("tb2-off.json"), load("tb2-on.json")
    claw_off = load("claw-off.json") or load("claw-off-overlap10.json")
    claw_on = load("claw-on.json") or load("claw-on-overlap10.json")

    def util_delta(off, on):
        if not off or not on:
            return None
        o, n = off.get("mean_reward"), on.get("mean_reward")
        if o is None or n is None:
            return None
        return {
            "off": o,
            "on": n,
            "delta": n - o,
            "off_n": off.get("n_total"),
            "on_n": on.get("n_total"),
            "off_tokens": (off.get("n_input_tokens") or 0) + (off.get("n_output_tokens") or 0),
            "on_tokens": (on.get("n_input_tokens") or 0) + (on.get("n_output_tokens") or 0),
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
            "does_lia_hurt_task_success_tb2": util_delta(tb2_off, tb2_on),
            "does_lia_hurt_task_success_claw": util_delta(claw_off, claw_on),
            "trust_catch_arm_c": c.get("catch_rate"),
            "trust_false_block_arm_c": c.get("false_block_rate"),
            "trust_overhead_arm_a_wall_mean_s": (a.get("overhead") or {}).get(
                "wall_time_seconds_mean"
            ),
            "trust_overhead_arm_a_tokens_mean": (a.get("overhead") or {}).get(
                "model_tokens_mean"
            ),
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
                "status": "MEASURED"
                if tb2_off and tb2_on
                else ("OFF_DONE" if tb2_off else "RUNNING"),
                "n_subset": 24,
                "off": tb2_off,
                "on": tb2_on,
                "delta": util_delta(tb2_off, tb2_on),
            },
            "claw-swe-lite": {
                "status": "MEASURED"
                if claw_off and claw_on
                else ("OFF_DONE" if claw_off else "PENDING"),
                "n_tasks": 80,
                "off": claw_off,
                "on": claw_on,
                "delta": util_delta(claw_off, claw_on),
            },
        },
    }
    (RES / "scorecard.json").write_text(json.dumps(score, indent=2) + "\n")
    print(json.dumps(score["daily_use"], indent=2))


if __name__ == "__main__":
    main()
