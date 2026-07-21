from __future__ import annotations

import json
import os
import secrets
import subprocess
import tempfile
from collections import Counter
from pathlib import Path

from harbor.agents.terminus_2.terminus_2 import Command, Terminus2
from harbor.models.agent.context import AgentContext

from .common import lia_bin

try:
    from bench.harbor.lia_decision import (
        fail_closed,
        journal_verification_decision,
        parse_gate_response,
        validate_receipt_head,
    )
except ModuleNotFoundError as error:
    if error.name not in {"bench", "bench.harbor"}:
        raise
    from lia_decision import (  # type: ignore[no-redef]
        fail_closed,
        journal_verification_decision,
        parse_gate_response,
        validate_receipt_head,
    )

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
        # P2-5: deny-only memo. Allows are always re-evaluated and rebound to the
        # current verified journal head; a cached allow can never outlive the TCB.
        self._decision_memo: dict[str, dict] = {}
        self._memo_hits = 0
        self._gate_spawns = 0
        self._signing_secret_hex = secrets.token_hex(32)
        self._init_durable_journal()

    @staticmethod
    def name() -> str:
        return "terminus-lia"

    def version(self) -> str | None:
        return "0.4.0"

    def _init_durable_journal(self) -> None:
        """Create the per-trial journal outside command-scoped temp directories."""
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
        fallback = (
            Path(tempfile.gettempdir())
            / "lia-trust"
            / "terminus-lia"
            / f"trial-{os.getpid()}-{secrets.token_hex(8)}"
        )
        fallback.mkdir(parents=True, mode=0o700)
        self._durable_journal = fallback / "lia-journal.db"

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

        Verified denials are memoized within a trial. Allows are always re-run
        and rebound to the current verified journal head.
        """
        key = self._canonical_cmd(command)
        cached = self._decision_memo.get(key)
        if cached is not None and cached.get("deny") is True:
            self._memo_hits += 1
            return dict(cached)
        if cached is not None:
            self._decision_memo.pop(key, None)

        try:
            binary = lia_bin()
        except FileNotFoundError as error:
            return fail_closed("LIA_GATE_UNAVAILABLE", str(error))

        if self._durable_journal is None:
            return fail_closed(
                "LIA_JOURNAL_UNAVAILABLE", "no durable per-trial journal path"
            )

        roots = self._workspace_roots()
        cwd = self._workspace_cwd()
        self._gate_spawns += 1
        try:
            timeout_seconds = max(
                0.1, float(os.environ.get("LIA_GATE_TIMEOUT_SECONDS", "10"))
            )
        except ValueError:
            timeout_seconds = 10.0
        try:
            temp_context = tempfile.TemporaryDirectory(prefix="terminus-lia-")
        except OSError as error:
            return fail_closed("LIA_GATE_IO_FAILED", str(error))
        with temp_context as tmp:
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
            try:
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
                self._durable_journal.parent.mkdir(parents=True, exist_ok=True)
            except OSError as error:
                return fail_closed("LIA_GATE_IO_FAILED", str(error))
            try:
                proc = subprocess.run(
                    [
                        str(binary),
                        "gate",
                        "--config",
                        str(cfg_path),
                        "--request",
                        str(req_path),
                        "--journal",
                        str(self._durable_journal),
                        "--secret-key-hex",
                        self._signing_secret_hex,
                        "--key-id",
                        "terminus-lia",
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=timeout_seconds,
                )
            except subprocess.TimeoutExpired as error:
                return fail_closed("LIA_GATE_TIMEOUT", str(error))
            except OSError as error:
                return fail_closed("LIA_GATE_UNAVAILABLE", str(error))

            decision = parse_gate_response(proc.stdout, proc.returncode, proc.stderr)
            try:
                verify = subprocess.run(
                    [str(binary), "journal-verify", str(self._durable_journal)],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=timeout_seconds,
                )
            except subprocess.TimeoutExpired as error:
                return fail_closed("LIA_JOURNAL_VERIFY_TIMEOUT", str(error))
            except OSError as error:
                return fail_closed("LIA_JOURNAL_VERIFY_UNAVAILABLE", str(error))
            verified = journal_verification_decision(
                verify.returncode, verify.stdout, verify.stderr
            )
            if verified["deny"]:
                return verified
            receipt_head = validate_receipt_head(decision, self._durable_journal)
            if receipt_head["deny"]:
                return receipt_head
            if decision["deny"]:
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
