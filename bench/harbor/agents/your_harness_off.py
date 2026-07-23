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
    write_agent_result,
)


class YourHarnessOff(BaseAgent):
    SUPPORTS_ATIF = False

    @staticmethod
    def name() -> str:
        return "your-harness-off"

    def version(self) -> str | None:
        return "0.2.0"

    async def setup(self, environment: BaseEnvironment) -> None:
        return None

    async def run(
        self,
        instruction: str,
        environment: BaseEnvironment,
        context: AgentContext,
    ) -> None:
        case_path = self._resolve_case_path(instruction, environment)
        case = load_case(case_path)
        model = self.model_name or pick_free_model(DEFAULT_BRIDGE)
        if "/" in model:
            model = model.split("/", 1)[-1]
        with tempfile.TemporaryDirectory(prefix="lia-harbor-off-") as tmp:
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
            completion_supported=False if is_adversarial(case) else True,
        )
        payload = {
            "arm": "A",
            "agent": self.name(),
            "lia_enforcing": False,
            "case": case,
            "trajectory": {
                "tool_name": traj["tool_name"],
                "tool_input": traj["tool_input"],
                "model": traj["model"],
            },
            "blocked": blocked,
            "metrics": metrics,
            "instruction": instruction,
        }
        write_agent_result(self.logs_dir, payload)
        traj_path = self.logs_dir / "trajectory.json"
        traj_path.write_text(json.dumps(payload["trajectory"], indent=2) + "\n")
        context.n_input_tokens = int(
            (traj.get("raw_response") or {}).get("usage", {}).get("input_tokens") or 0
        )
        context.n_output_tokens = int(
            (traj.get("raw_response") or {}).get("usage", {}).get("output_tokens") or 0
        )
        context.exit_code = 0
        context.metadata = {"metrics": metrics, "case_id": case.get("id")}

    def _resolve_case_path(
        self, instruction: str, environment: BaseEnvironment
    ) -> Path:
        marker = "CASE_PATH="
        for line in instruction.splitlines():
            if line.startswith(marker):
                return Path(line[len(marker) :].strip())
        candidate = Path("/task/case.json")
        return candidate
