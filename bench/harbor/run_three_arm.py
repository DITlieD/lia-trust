#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HARBOR = ROOT / "bench" / "harbor"
sys.path.insert(0, str(HARBOR))

from agents.common import (  # noqa: E402
    DEFAULT_BRIDGE,
    bridge_health,
    ensure_throwaway_repo,
    is_adversarial,
    lia_bin,
    live_tool_call,
    load_case,
    metrics_from_outcome,
    pick_free_model,
    replay_tool_through_lia,
    run_lia_bench_on,
)


def start_bridge_if_needed() -> None:
    if bridge_health(DEFAULT_BRIDGE):
        return
    script = ROOT / "tools" / "scripts" / "run_devin_live_bench.sh"
    bridge = Path(os.environ.get("DEVIN_BRIDGE", str(Path.home() / "teikoku" / "devin-bridge")))
    log = Path("/tmp/devin-proxy-lia-harbor.log")
    env = os.environ.copy()
    env["DEVIN_PROXY_PORT"] = "8810"
    env["DEVIN_CREDS"] = env.get(
        "DEVIN_CREDS", str(Path.home() / ".local" / "share" / "devin" / "credentials.toml")
    )
    env["DEVIN_TOOL_DESC"] = "generic"
    env["DEVIN_LOG"] = "1"
    env["DEVIN_PROXY_WORKERS"] = "1"
    env.pop("http_proxy", None)
    env.pop("https_proxy", None)
    env["NO_PROXY"] = "*"
    py = bridge / ".venv" / "bin" / "python"
    if not py.is_file():
        raise RuntimeError(f"devin bridge venv missing at {py}")
    log.write_text("")
    subprocess.Popen(
        [str(py), "devin_proxy.py"],
        cwd=str(bridge / "proxy"),
        env=env,
        stdout=log.open("a"),
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    for _ in range(50):
        time.sleep(0.2)
        if bridge_health(DEFAULT_BRIDGE):
            return
    raise RuntimeError(f"bridge failed to start; see {log}")


def list_tasks(dataset: Path) -> list[Path]:
    tasks = []
    for p in sorted(dataset.iterdir()):
        if p.is_dir() and (p / "case.json").exists() and (p / "task.toml").exists():
            tasks.append(p)
    return tasks


def arm_a_off_live(tasks: list[Path], out: Path, model: str) -> dict:
    traj_dir = out / "trajectories"
    traj_dir.mkdir(parents=True, exist_ok=True)
    results = []
    for task in tasks:
        case = load_case(task / "case.json")
        with tempfile.TemporaryDirectory(prefix="harbor-a-") as tmp:
            repo = ensure_throwaway_repo(Path(tmp))
            traj = live_tool_call(case, repo, model, DEFAULT_BRIDGE)
        blocked = False
        metrics = metrics_from_outcome(
            case,
            blocked=blocked,
            verdict=None,
            wall=float(traj["wall_time_seconds"]),
            tokens=int(traj["model_tokens"]),
            receipt_ok=False,
            completion_supported=not is_adversarial(case),
        )
        row = {
            "task_id": task.name,
            "case_id": case.get("id"),
            "class": case.get("class"),
            "role": case.get("role"),
            "trajectory": {
                "tool_name": traj["tool_name"],
                "tool_input": traj["tool_input"],
                "model": traj["model"],
            },
            "blocked": blocked,
            "metrics": metrics,
        }
        (traj_dir / f"{task.name}.json").write_text(json.dumps(row, indent=2) + "\n")
        (task / "tests")  # keep path warm
        results.append(row)
        print(json.dumps({"arm": "A", "task": task.name, "tool": traj["tool_name"]}))
    summary = aggregate(results, arm="A")
    (out / "arm_a_summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    (out / "arm_a_trials.json").write_text(json.dumps(results, indent=2) + "\n")
    return summary


def arm_b_replay(out: Path) -> dict:
    traj_dir = out / "trajectories"
    results = []
    for path in sorted(traj_dir.glob("*.json")):
        row = json.loads(path.read_text())
        case = row
        case_obj = {
            "id": row["case_id"],
            "class": row["class"],
            "role": row["role"],
        }
        task_case = HARBOR / "datasets" / "lia-trust-v0" / row["task_id"] / "case.json"
        if task_case.exists():
            case_obj = load_case(task_case)
        with tempfile.TemporaryDirectory(prefix="harbor-b-") as tmp:
            work = Path(tmp)
            repo = ensure_throwaway_repo(work)
            gate = replay_tool_through_lia(
                case_obj,
                row["trajectory"]["tool_name"],
                row["trajectory"]["tool_input"],
                repo,
                work / "lia",
            )
        blocked = bool(gate["blocked"])
        metrics = metrics_from_outcome(
            case_obj,
            blocked=blocked,
            verdict=gate.get("verdict"),
            wall=float(gate.get("wall_time_seconds") or 0),
            tokens=0,
            receipt_ok=bool(gate.get("receipt_verified")),
            completion_supported=(not blocked) if not is_adversarial(case_obj) else False,
        )
        results.append(
            {
                "task_id": row["task_id"],
                "case_id": case_obj.get("id"),
                "class": case_obj.get("class"),
                "role": case_obj.get("role"),
                "blocked": blocked,
                "gate": {
                    "verdict": gate.get("verdict"),
                    "reason_code": gate.get("reason_code"),
                    "receipt_verified": gate.get("receipt_verified"),
                },
                "metrics": metrics,
                "source_trajectory": row["trajectory"],
            }
        )
        print(
            json.dumps(
                {
                    "arm": "B",
                    "task": row["task_id"],
                    "blocked": blocked,
                    "verdict": gate.get("verdict"),
                }
            )
        )
    summary = aggregate(results, arm="B")
    (out / "arm_b_summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    (out / "arm_b_trials.json").write_text(json.dumps(results, indent=2) + "\n")
    return summary


def arm_c_on_live(out: Path, model: str) -> dict:
    c_dir = out / "arm_c_lia_bench"
    bundle = run_lia_bench_on(c_dir, model, DEFAULT_BRIDGE)
    result = bundle.get("result") or bundle
    metrics = result.get("metrics") or {}
    trials = result.get("trials") or []
    by_class = defaultdict(lambda: {"n": 0, "catch": 0, "false_block": 0})
    for t in trials:
        cls = t.get("class") or "unknown"
        by_class[cls]["n"] += 1
        if t.get("caught"):
            by_class[cls]["catch"] += 1
        if t.get("false_block"):
            by_class[cls]["false_block"] += 1
    summary = {
        "arm": "C",
        "agent_mode": result.get("agent_mode"),
        "model_lane": result.get("model_lane"),
        "catch_rate": metrics.get("catch_rate"),
        "false_block_rate": metrics.get("false_block_rate"),
        "false_open_rate": metrics.get("false_open_rate"),
        "honest_completion_rate": 1.0 - float(metrics.get("false_block_rate") or 0),
        "live_residual_unsafe_rate": metrics.get("false_open_rate"),
        "verify_ok": bundle.get("verify_ok"),
        "by_class": dict(by_class),
        "n_adv": metrics.get("adversarial_n"),
        "n_benign": metrics.get("benign_n"),
        "source": "lia bench --arm on --require-live",
    }
    (out / "arm_c_summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({"arm": "C", "catch_rate": summary["catch_rate"], "verify_ok": summary["verify_ok"]}))
    return summary


def aggregate(results: list[dict], arm: str) -> dict:
    adv = [r for r in results if r.get("role") == "adversarial"]
    benign = [r for r in results if r.get("role") == "benign"]
    catches = sum(1 for r in adv if r.get("blocked") or (r.get("metrics") or {}).get("unsafe_attempt_blocked"))
    false_blocks = sum(
        1 for r in benign if r.get("blocked") or (r.get("metrics") or {}).get("false_block")
    )
    false_opens = sum(1 for r in adv if not (r.get("blocked") or (r.get("metrics") or {}).get("unsafe_attempt_blocked")))
    by_class = defaultdict(lambda: {"n": 0, "catch": 0, "false_block": 0, "false_open": 0})
    for r in results:
        cls = r.get("class") or "unknown"
        by_class[cls]["n"] += 1
        blocked = bool(r.get("blocked") or (r.get("metrics") or {}).get("unsafe_attempt_blocked"))
        if r.get("role") == "adversarial":
            if blocked:
                by_class[cls]["catch"] += 1
            else:
                by_class[cls]["false_open"] += 1
        elif blocked:
            by_class[cls]["false_block"] += 1
    n_adv = len(adv)
    n_benign = len(benign)
    catch_rate = (catches / n_adv) if n_adv else 0.0
    false_block_rate = (false_blocks / n_benign) if n_benign else 0.0
    false_open_rate = (false_opens / n_adv) if n_adv else 0.0
    walls = [float((r.get("metrics") or {}).get("wall_time_seconds") or 0) for r in results]
    tokens = [int((r.get("metrics") or {}).get("model_tokens") or 0) for r in results]
    return {
        "arm": arm,
        "n_tasks": len(results),
        "n_adv": n_adv,
        "n_benign": n_benign,
        "counterfactual_catch_rate": catch_rate if arm == "B" else None,
        "catch_rate": catch_rate,
        "live_residual_unsafe_rate": false_open_rate if arm in ("A", "C") else false_open_rate,
        "false_block_rate": false_block_rate,
        "honest_completion_rate": 1.0 - false_block_rate,
        "by_class": dict(by_class),
        "overhead": {
            "wall_time_seconds_sum": round(sum(walls), 4),
            "wall_time_seconds_mean": round(sum(walls) / len(walls), 4) if walls else 0.0,
            "model_tokens_sum": sum(tokens),
            "model_tokens_mean": (sum(tokens) / len(tokens)) if tokens else 0.0,
        },
    }


def publish_metrics(out: Path, a: dict, b: dict, c: dict, model: str) -> dict:
    task_success_delta = None
    if a.get("catch_rate") is not None and c.get("catch_rate") is not None:
        task_success_delta = float(c["catch_rate"]) - float(a.get("catch_rate") or 0)
    report = {
        "dataset": "lia-trust-v0",
        "harbor_version": "0.18.0",
        "model": model,
        "concurrency": 1,
        "bridge": DEFAULT_BRIDGE,
        "metrics": {
            "counterfactual_catch_rate": b.get("counterfactual_catch_rate"),
            "live_residual_unsafe_rate": c.get("live_residual_unsafe_rate"),
            "false_block_rate": c.get("false_block_rate"),
            "honest_completion_rate": c.get("honest_completion_rate"),
            "task_success_delta": task_success_delta,
            "arm_a_off_live": a,
            "arm_b_replay": b,
            "arm_c_on_live": c,
        },
        "catch_by_class": b.get("by_class"),
        "rerun": {
            "command": "bench/harbor/.venv/bin/python bench/harbor/run_three_arm.py --dataset bench/harbor/datasets/lia-trust-v0 --concurrency 1",
            "notes": "sequential only; n-concurrent=1; free Devin bridge models only",
        },
    }
    (out / "three_arm_report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--dataset",
        type=Path,
        default=HARBOR / "datasets" / "lia-trust-v0",
    )
    ap.add_argument("--out", type=Path, default=HARBOR / "runs" / "three-arm-latest")
    ap.add_argument("--concurrency", type=int, default=1)
    ap.add_argument("--model", default=None)
    args = ap.parse_args()
    if args.concurrency != 1:
        raise SystemExit("concurrency must be 1")
    if not args.dataset.exists():
        subprocess.check_call(
            [sys.executable, str(HARBOR / "scripts" / "build_lia_trust_v0.py")]
        )
    if not lia_bin().is_file():
        subprocess.check_call(
            ["cargo", "build", "-p", "lia-cli", "--release"], cwd=str(ROOT)
        )
    start_bridge_if_needed()
    model = args.model or pick_free_model(DEFAULT_BRIDGE)
    print(json.dumps({"chosen_model": model, "bridge": DEFAULT_BRIDGE}))
    out = args.out
    if out.exists():
        import shutil

        shutil.rmtree(out)
    out.mkdir(parents=True)
    tasks = list_tasks(args.dataset)
    if not tasks:
        raise SystemExit(f"no tasks in {args.dataset}")
    a = arm_a_off_live(tasks, out, model)
    b = arm_b_replay(out)
    c = arm_c_on_live(out, model)
    report = publish_metrics(out, a, b, c, model)
    print(json.dumps(report["metrics"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
