from __future__ import annotations

import json
import tempfile
from pathlib import Path

from harbor.agents.base import BaseAgent
from harbor.environments.base import BaseEnvironment
from harbor.models.agent.context import AgentContext

from .common import (
    DEFAULT_BRIDGE,
    ensure_throwaway_repo,
    is_adversarial,
    live_tool_call,
    load_case,
    metrics_from_outcome,
    pick_free_model,
    replay_tool_through_lia,
    write_agent_result,
)


class YourHarnessLia(BaseAgent):
    SUPPORTS_ATIF = False

    @staticmethod
    def name() -> str:
        return "your-harness-lia"

    def version(self) -> str | None:
        return "0.1.0"

    async def setup(self, environment: BaseEnvironment) -> None:
        return None

    async def run(
        self,
        instruction: str,
        environment: BaseEnvironment,
        context: AgentContext,
    ) -> None:
        case_path = self._resolve_case_path(instruction)
        case = load_case(case_path)
        model = self.model_name or pick_free_model(DEFAULT_BRIDGE)
        if "/" in model:
            model = model.split("/", 1)[-1]
        with tempfile.TemporaryDirectory(prefix="lia-harbor-lia-") as tmp:
            work = Path(tmp)
            repo = ensure_throwaway_repo(work)
            traj = live_tool_call(case, repo, model, DEFAULT_BRIDGE)
            gate = replay_tool_through_lia(
                case,
                traj["tool_name"],
                traj["tool_input"],
                repo,
                work / "lia-out",
            )
        blocked = bool(gate["blocked"])
        metrics = metrics_from_outcome(
            case,
            blocked=blocked,
            verdict=gate.get("verdict"),
            wall=float(traj["wall_time_seconds"]) + float(gate.get("wall_time_seconds") or 0),
            tokens=int(traj["model_tokens"]),
            receipt_ok=bool(gate.get("receipt_verified")),
            completion_supported=(not blocked) if not is_adversarial(case) else False,
        )
        payload = {
            "arm": "C",
            "agent": self.name(),
            "lia_enforcing": True,
            "case": case,
            "trajectory": {
                "tool_name": traj["tool_name"],
                "tool_input": traj["tool_input"],
                "model": traj["model"],
            },
            "gate": gate,
            "blocked": blocked,
            "metrics": metrics,
            "instruction": instruction,
        }
        write_agent_result(self.logs_dir, payload)
        (self.logs_dir / "trajectory.json").write_text(
            json.dumps(payload["trajectory"], indent=2) + "\n"
        )
        context.n_input_tokens = int(
            (traj.get("raw_response") or {}).get("usage", {}).get("input_tokens") or 0
        )
        context.n_output_tokens = int(
            (traj.get("raw_response") or {}).get("usage", {}).get("output_tokens") or 0
        )
        context.exit_code = 0
        context.metadata = {"metrics": metrics, "case_id": case.get("id")}

    def _resolve_case_path(self, instruction: str) -> Path:
        marker = "CASE_PATH="
        for line in instruction.splitlines():
            if line.startswith(marker):
                return Path(line[len(marker) :].strip())
        return Path("/task/case.json")
