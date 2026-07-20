from __future__ import annotations

import json
import os
import subprocess
import tempfile
from collections import Counter
from pathlib import Path

from harbor.agents.terminus_2.terminus_2 import Command, Terminus2
from harbor.models.agent.context import AgentContext

from .common import lia_bin

# Hard-stop reason codes: strip command, no soft rewrite.
HARD_DENY_REASONS = frozenset(
    {
        "SHELL_DESTRUCTIVE",
        "SHELL_COMMAND_SUBSTITUTION",
    }
)

# Soft scope denials get a recovery hint (still DENY, never fail-open).
SOFT_SCOPE_REASONS = frozenset(
    {
        "SHELL_OUT_OF_SCOPE",
        "SHELL_PROTECTED_PATH",
        "FS_OUT_OF_SCOPE",
        "FS_PROTECTED_PATH",
        "FS_SYMLINK_ESCAPE",
    }
)

# Common Harbor / TB2 / Claw task mounts. Prefer env LIA_ALLOWED_ROOTS when set.
DEFAULT_HARBOR_ROOTS = (
    "/app",
    "/testbed",
    "/git",
    "/var/www",
    "/home/agent",
    "/tmp",
)
DEFAULT_DENY_CAP = 3


class TerminusLia(Terminus2):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._deny_counts: Counter[str] = Counter()
        self._deny_by_reason: Counter[str] = Counter()
        self._durable_journal: Path | None = None
        # P2-5: short-TTL allow/deny memo keyed by canonical command (no re-spawn)
        self._decision_memo: dict[str, dict] = {}
        self._memo_hits = 0
        self._gate_spawns = 0
        self._hl4_observations: list[dict] = []
        self._init_durable_journal()

    @staticmethod
    def name() -> str:
        return "terminus-lia"

    def version(self) -> str | None:
        return "0.3.0"

    def _init_durable_journal(self) -> None:
        """Optional durable journal outside the empty tempfile (P0-6)."""
        override = os.environ.get("LIA_JOURNAL_PATH") or os.environ.get("LIA_JOURNAL_DIR")
        if override:
            p = Path(override)
            if p.suffix == ".db" or p.name.endswith(".sqlite"):
                p.parent.mkdir(parents=True, exist_ok=True)
                self._durable_journal = p
            else:
                p.mkdir(parents=True, exist_ok=True)
                self._durable_journal = p / "terminus-lia-journal.db"
            return
        # Prefer Harbor trial logs dir if present on the agent instance.
        for attr in ("logs_dir", "trial_dir", "output_dir", "agent_dir"):
            cand = getattr(self, attr, None)
            if cand:
                base = Path(str(cand))
                try:
                    base.mkdir(parents=True, exist_ok=True)
                    self._durable_journal = base / "lia-journal.db"
                    return
                except OSError:
                    continue

    def _workspace_roots(self) -> list[str]:
        """Real Harbor task mounts, not empty tempfile (P0-1).

        Prefer container task roots (/app, /testbed, /git) over the host PWD/HOME
        of the Harbor agent process (which is the monorepo, not the trial FS).
        """
        roots: list[str] = []
        env_roots = os.environ.get("LIA_ALLOWED_ROOTS", "")
        if env_roots.strip():
            for r in env_roots.replace(",", os.pathsep).split(os.pathsep):
                r = r.strip()
                if r and r not in roots:
                    roots.append(r)
        # Task mounts first (product intent for Harbor utility).
        for r in DEFAULT_HARBOR_ROOTS:
            if r not in roots:
                roots.append(r)
        # Optional host/workspace extras last (do not let host PWD dominate cwd).
        for key in ("LIA_WORKSPACE",):
            v = os.environ.get(key)
            if v and v.startswith("/") and v not in roots:
                roots.append(v)
        return [r for r in roots if r.startswith("/")]

    def _workspace_cwd(self) -> str:
        # Prefer explicit LIA_CWD or task roots — never host monorepo PWD.
        v = os.environ.get("LIA_CWD")
        if v and v.startswith("/"):
            return v
        roots = self._workspace_roots()
        for preferred in ("/app", "/testbed", "/git", "/home/agent"):
            if preferred in roots:
                return preferred
        return roots[0] if roots else "/app"

    def _deny_cap(self) -> int:
        raw = os.environ.get("LIA_DENY_CAP", str(DEFAULT_DENY_CAP))
        try:
            return max(1, int(raw))
        except ValueError:
            return DEFAULT_DENY_CAP

    async def _execute_commands(self, commands: list[Command], session) -> tuple[bool, str]:
        gated: list[Command] = []
        denied_msgs: list[str] = []
        for command in commands:
            text = (command.keystrokes or "").strip()
            if not text:
                gated.append(command)
                continue
            decision = self._lia_shell_decision(text)
            if decision["deny"]:
                reason = decision.get("reason_code") or "SHELL_DENY"
                self._deny_by_reason[reason] += 1
                # Cap identical command denials (P0-3)
                key = f"{reason}|{text[:120]}"
                self._deny_counts[key] += 1
                if self._deny_counts[key] > self._deny_cap():
                    denied_msgs.append(
                        f"[lia] deny-cap reached for {reason}; stop retrying identical command"
                    )
                    continue
                msg = self._format_deny_message(text, decision)
                denied_msgs.append(msg)
                # Hard-stop: never forward. Soft OOS: still never forward (fail-closed),
                # but message includes recovery rewrite (P0-2).
                continue
            gated.append(command)
        if denied_msgs and not gated:
            return False, "LIA denied shell: " + " | ".join(denied_msgs)
        timeout, output = await super()._execute_commands(gated, session)
        if denied_msgs:
            output = (output or "") + "\n" + "\n".join(denied_msgs)
        # Emit deny_by_reason snapshot for Harbor result collectors (P0-7 / P2-2)
        if self._deny_by_reason:
            hist = dict(self._deny_by_reason)
            output = (output or "") + f"\n[lia] deny_by_reason={json.dumps(hist, sort_keys=True)}"
        return timeout, output

    def _format_deny_message(self, command: str, decision: dict) -> str:
        reason = decision.get("reason_code") or "SHELL_DENY"
        detail = decision.get("detail") or ""
        snippet = command[:200].replace("\n", " ")
        if reason in SOFT_SCOPE_REASONS:
            roots = ", ".join(self._workspace_roots()[:4])
            cwd = self._workspace_cwd()
            return (
                f"[lia] denied reason_code={reason}: {snippet} "
                f"(paths must stay under allowed_roots=[{roots}] cwd={cwd}; "
                f"rewrite absolute paths into the workspace. detail={detail})"
            )
        if reason in HARD_DENY_REASONS:
            return (
                f"[lia] denied reason_code={reason} (hard irreversible): {snippet} "
                f"detail={detail}"
            )
        return f"[lia] denied reason_code={reason}: {snippet} detail={detail}"

    def _lia_denies_shell(self, command: str) -> bool:
        """Back-compat boolean API used by tests/callers."""
        return bool(self._lia_shell_decision(command).get("deny"))

    def _canonical_cmd(self, command: str) -> str:
        return " ".join(command.strip().split())

    def _lia_shell_decision(self, command: str) -> dict:
        """Return {deny, reason_code, detail, verdict} from real lia gate CLI.

        Identical commands within a trial hit an in-memory memo (P2-5) so lia is
        not re-spawned for the same keystrokes.
        """
        key = self._canonical_cmd(command)
        if key in self._decision_memo:
            self._memo_hits += 1
            return dict(self._decision_memo[key])

        try:
            binary = lia_bin()
        except FileNotFoundError:
            return {"deny": False, "reason_code": None, "detail": "no-lia-bin"}

        roots = self._workspace_roots()
        cwd = self._workspace_cwd()
        self._gate_spawns += 1
        with tempfile.TemporaryDirectory(prefix="terminus-lia-") as tmp:
            work = Path(tmp)
            cfg = {
                "allowed_roots": roots,
                "home_dir": os.environ.get("HOME", "/home/agent"),
                "cwd": cwd,
                "protected_paths": [f"{r}/.lia" for r in roots if r in ("/app", "/testbed")],
                "registry": {},
                "env": {
                    "HOME": os.environ.get("HOME", "/home/agent"),
                    "PWD": cwd,
                },
            }
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
            journal = self._durable_journal or (work / "journal.db")
            if self._durable_journal:
                journal.parent.mkdir(parents=True, exist_ok=True)
            proc = subprocess.run(
                [
                    str(binary),
                    "gate",
                    "--config",
                    str(cfg_path),
                    "--request",
                    str(req_path),
                    "--journal",
                    str(journal),
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
                return {
                    "deny": False,
                    "reason_code": None,
                    "detail": (proc.stderr or "")[:200],
                }
            try:
                parsed = json.loads(proc.stdout)
            except json.JSONDecodeError:
                return {"deny": False, "reason_code": None, "detail": "bad-json"}

            reason_code = None
            detail = None
            verdicts: list[str] = []
            for o in parsed.get("outcomes") or []:
                if isinstance(o, dict):
                    if o.get("verdict"):
                        verdicts.append(str(o["verdict"]).lower())
                    if o.get("reason_code") and reason_code is None:
                        reason_code = str(o["reason_code"])
                    if o.get("detail") and detail is None:
                        detail = str(o["detail"])
            overall = parsed.get("overall")
            if isinstance(overall, str):
                verdicts.append(overall.lower())
            elif isinstance(overall, dict):
                if overall.get("verdict"):
                    verdicts.append(str(overall["verdict"]).lower())
                if overall.get("reason_code") and reason_code is None:
                    reason_code = str(overall["reason_code"])

            deny = any(v in {"deny", "refuted", "unsupported", "quarantine"} for v in verdicts)
            decision = {
                "deny": deny,
                "reason_code": reason_code,
                "detail": detail,
                "verdicts": verdicts,
            }
            self._decision_memo[key] = decision
            return dict(decision)

    def deny_by_reason_histogram(self) -> dict[str, int]:
        """Exporter for Harbor result collectors."""
        return dict(self._deny_by_reason)

    def memo_stats(self) -> dict[str, int]:
        return {
            "memo_hits": self._memo_hits,
            "gate_spawns": self._gate_spawns,
            "memo_size": len(self._decision_memo),
        }

    def _looks_like_test_command(self, command: str) -> bool:
        c = command.lower()
        return any(
            tok in c
            for tok in (
                "pytest",
                "cargo test",
                "npm test",
                "go test",
                "python -m unittest",
                "nosetests",
            )
        )

    def record_hl4_observation(
        self, command: str, exit_code: int, stdout: str = "", stderr: str = ""
    ) -> dict | None:
        """Optional HL-4 wrapper observation for detectable test commands (P2-17)."""
        if not self._looks_like_test_command(command):
            return None
        import hashlib

        def h(s: str) -> str:
            return hashlib.sha256(s.encode()).hexdigest()

        obs = {
            "exit_code": exit_code,
            "stdout_sha256": h(stdout),
            "stderr_sha256": h(stderr),
            "argv": command.strip().split(),
            "cwd": self._workspace_cwd(),
            "coverage_profraw_sha256": h(""),
            "wrapper_digest_sha256": h("terminus-lia-hl4-v1"),
            "command": command[:500],
        }
        self._hl4_observations.append(obs)
        # Persist beside durable journal when available
        if self._durable_journal:
            path = self._durable_journal.parent / "hl4-observations.jsonl"
            try:
                with path.open("a") as f:
                    f.write(json.dumps(obs) + "\n")
            except OSError:
                pass
        return obs

    def maybe_completion_gate(self, modified_paths: list[str], has_test_result: bool) -> dict:
        """Optional evidence-completeness check when agent claims done (P1-14)."""
        try:
            binary = lia_bin()
        except FileNotFoundError:
            return {"deny": False, "detail": "no-lia-bin"}
        roots = self._workspace_roots()
        cwd = self._workspace_cwd()
        with tempfile.TemporaryDirectory(prefix="terminus-complete-") as tmp:
            work = Path(tmp)
            cfg = {
                "allowed_roots": roots,
                "home_dir": os.environ.get("HOME", "/home/agent"),
                "cwd": cwd,
                "protected_paths": [],
                "registry": {},
                "env": {"HOME": os.environ.get("HOME", "/home/agent")},
            }
            req = {
                "gate_id": "evidence-completeness",
                "action_id": "00000000-0000-4000-8000-000000000099",
                "kind": "complete_task",
                "payload": {
                    "modified_paths": modified_paths,
                    "has_test_result": has_test_result,
                    "new_dependencies": [],
                    "deps_registry_evidence": True,
                },
            }
            (work / "c.json").write_text(json.dumps(cfg))
            (work / "r.json").write_text(json.dumps(req))
            proc = subprocess.run(
                [
                    str(binary),
                    "gate",
                    "--config",
                    str(work / "c.json"),
                    "--request",
                    str(work / "r.json"),
                    "--journal",
                    str(work / "j.db"),
                    "--secret-key-hex",
                    "55" * 32,
                    "--key-id",
                    "terminus-complete",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            try:
                parsed = json.loads(proc.stdout or "{}")
                o = (parsed.get("outcomes") or [{}])[0]
                return {
                    "deny": str(o.get("verdict", "")).lower()
                    in {"deny", "incomplete", "refuted", "unsupported"},
                    "verdict": o.get("verdict"),
                    "reason_code": o.get("reason_code"),
                    "detail": o.get("detail"),
                }
            except json.JSONDecodeError:
                return {"deny": False, "detail": "bad-json"}
