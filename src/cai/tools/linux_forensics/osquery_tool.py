from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Iterable

from cai.sdk.agents import function_tool


def _get_linux_tools_dir() -> Path:
    env_dir = os.getenv("CAI_LINUX_TOOLS_DIR")
    if env_dir:
        return Path(env_dir).resolve()
    repo_root = Path(__file__).resolve().parents[3]
    return (repo_root / "tools" / "linux").resolve()


def _find_binary(candidates: Iterable[Path | str]) -> Path | None:
    for candidate in candidates:
        path = Path(candidate)
        if path.is_file():
            return path.resolve()
        found = shutil.which(str(candidate))
        if found:
            return Path(found).resolve()
    return None


def _run_command(args: list[str], timeout_s: int = 300) -> dict:
    start = time.time()
    try:
        proc = subprocess.run(
            args,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            encoding="utf-8",
            errors="replace",
        )
        return {
            "ok": proc.returncode == 0,
            "args": args,
            "exit_code": proc.returncode,
            "stdout": proc.stdout[:12000],
            "stderr": proc.stderr[:12000],
            "duration_ms": int((time.time() - start) * 1000),
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "ok": False,
            "args": args,
            "exit_code": -1,
            "stdout": (exc.stdout or "")[:12000],
            "stderr": f"Timeout after {timeout_s}s",
            "duration_ms": int((time.time() - start) * 1000),
        }


def _format_plan_output(result: dict) -> str:
    if not result.get("ok"):
        searched = result.get("searched_paths", [])
        searched_text = "\n".join(f"- {p}" for p in searched) if searched else "- (none)"
        return (
            "Status: error\n"
            "Tool: osquery\n"
            f"Message: {result.get('error', 'unknown error')}\n"
            f"Searched paths:\n{searched_text}"
        )

    lines = [
        "Status: ok",
        "Tool: osquery",
        f"Mode: {result.get('mode', 'plan_only')}",
        f"Execute: {result.get('execute', False)}",
        f"Command: {' '.join(result.get('args', []))}",
        f"Notes: {result.get('notes', '')}",
    ]

    run_result = result.get("run_result")
    if run_result:
        lines.extend(
            [
                "Execution:",
                f"- ok: {run_result.get('ok')}",
                f"- exit_code: {run_result.get('exit_code')}",
                f"- duration_ms: {run_result.get('duration_ms')}",
                f"- stdout: {run_result.get('stdout', '').strip() or '(empty)'}",
                f"- stderr: {run_result.get('stderr', '').strip() or '(empty)'}",
            ]
        )

    return "\n".join(lines)


def build_osquery_plan_dict(sql: str = "select * from processes limit 20;", execute: bool = False, timeout_s: int = 300) -> dict:
    tools_dir = _get_linux_tools_dir()
    bin_path = tools_dir / "osquery" / "osqueryi"
    tool = _find_binary([bin_path, "osqueryi"])
    if not tool:
        return {
            "ok": False,
            "tool": "osquery",
            "error": "osqueryi not found",
            "searched_paths": [str(bin_path), "osqueryi"],
        }

    args = [str(tool), "--json", sql]
    result = {
        "ok": True,
        "tool": "osquery",
        "mode": "plan_only",
        "execute": execute,
        "args": args,
        "notes": "SQL query can be customized.",
    }
    if execute:
        result["run_result"] = _run_command(args=args, timeout_s=timeout_s)
    return result


@function_tool
def build_osquery_plan(
    sql: str = "select * from processes limit 20;", execute: bool = False, timeout_s: int = 300
) -> str:
    return _format_plan_output(
        build_osquery_plan_dict(sql=sql, execute=execute, timeout_s=timeout_s)
    )
