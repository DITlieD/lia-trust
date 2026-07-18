from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path

from harbor.agents.terminus_2.terminus_2 import Command, Terminus2
from harbor.models.agent.context import AgentContext

from .common import lia_bin


class TerminusLia(Terminus2):
    @staticmethod
    def name() -> str:
        return "terminus-lia"

    def version(self) -> str | None:
        return "0.1.0"

    async def _execute_commands(self, commands: list[Command], session) -> tuple[bool, str]:
        gated: list[Command] = []
        denied: list[str] = []
        for command in commands:
            text = (command.keystrokes or "").strip()
            if text and self._lia_denies_shell(text):
                denied.append(text[:200])
                continue
            gated.append(command)
        if denied and not gated:
            msg = "LIA denied irreversible shell: " + " | ".join(denied)
            return False, msg
        timeout, output = await super()._execute_commands(gated, session)
        if denied:
            output = (output or "") + "\n[lia] denied: " + " | ".join(denied)
        return timeout, output

    def _lia_denies_shell(self, command: str) -> bool:
        try:
            binary = lia_bin()
        except FileNotFoundError:
            return False
        with tempfile.TemporaryDirectory(prefix="terminus-lia-") as tmp:
            work = Path(tmp)
            cfg = {
                "allowed_roots": [str(work / "repo")],
                "home_dir": "/home/agent",
                "cwd": str(work / "repo"),
                "protected_paths": [],
                "registry": {},
                "env": {"HOME": "/home/agent"},
            }
            (work / "repo").mkdir()
            cfg_path = work / "gate-config.json"
            req_path = work / "request.json"
            cfg_path.write_text(json.dumps(cfg))
            req_path.write_text(
                json.dumps(
                    {
                        "gate_id": "shell-irreversible",
                        "action_id": "00000000-0000-4000-8000-000000000001",
                        "kind": "shell",
                        "payload": {"command": command},
                    }
                )
            )
            proc = subprocess.run(
                [
                    str(binary),
                    "gate",
                    "--config",
                    str(cfg_path),
                    "--request",
                    str(req_path),
                    "--journal",
                    str(work / "journal.db"),
                    "--secret-key-hex",
                    "55" * 32,
                    "--key-id",
                    "terminus-lia",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            if not proc.stdout.strip():
                return False
            try:
                parsed = json.loads(proc.stdout)
            except json.JSONDecodeError:
                return False
            verdicts = []
            for o in parsed.get("outcomes") or []:
                if isinstance(o, dict) and o.get("verdict"):
                    verdicts.append(str(o["verdict"]).lower())
            overall = parsed.get("overall")
            if isinstance(overall, str):
                verdicts.append(overall.lower())
            elif isinstance(overall, dict) and overall.get("verdict"):
                verdicts.append(str(overall["verdict"]).lower())
            return any(v in {"deny", "refuted", "unsupported", "quarantine"} for v in verdicts)
