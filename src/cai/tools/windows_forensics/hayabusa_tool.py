from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path
from typing import Iterable

from cai.sdk.agents import function_tool


def _get_windows_tools_dir() -> Path:
    env_dir = os.getenv("CAI_WINDOWS_TOOLS_DIR")
    if env_dir:
        return Path(env_dir).resolve()
    repo_root = Path(__file__).resolve().parents[3]
    return (repo_root / "tools" / "windows").resolve()


def _find_binary(candidates: Iterable[Path | str]) -> Path | None:
    for candidate in candidates:
        path = Path(candidate)
        if path.is_file():
            return path.resolve()
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
            "Tool: hayabusa\n"
            f"Message: {result.get('error', 'unknown error')}\n"
            f"Searched paths:\n{searched_text}"
        )

    lines = [
        "Status: ok",
        "Tool: hayabusa",
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


def build_hayabusa_plan_dict(evtx_dir: str, execute: bool = False, timeout_s: int = 300) -> dict:
    tools_dir = _get_windows_tools_dir()
    exe_path = tools_dir / "hayabusa" / "hayabusa.exe"
    tool = _find_binary([exe_path])
    if not tool:
        return {
            "ok": False,
            "tool": "hayabusa",
            "error": "hayabusa.exe not found",
            "searched_paths": [str(exe_path)],
        }

    args = [str(tool), "csv-timeline", "-d", str(Path(evtx_dir).resolve()), "--no-wizard"]
    result = {
        "ok": True,
        "tool": "hayabusa",
        "mode": "plan_only",
        "execute": execute,
        "args": args,
        "notes": "Output and rule path are deferred.",
    }
    if execute:
        result["run_result"] = _run_command(args=args, timeout_s=timeout_s)
    return result


@function_tool
def build_hayabusa_plan(evtx_dir: str, execute: bool = False, timeout_s: int = 300) -> str:
    return _format_plan_output(
        build_hayabusa_plan_dict(evtx_dir=evtx_dir, execute=execute, timeout_s=timeout_s)
    )
