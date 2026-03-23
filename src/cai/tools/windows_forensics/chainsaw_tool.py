from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path
from typing import Iterable

from cai.sdk.agents import function_tool
from cai.tools.forensics_common import enrich_run_result, format_plan_output_generic


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
        return enrich_run_result({
            "ok": proc.returncode == 0,
            "args": args,
            "exit_code": proc.returncode,
            "stdout": proc.stdout[:12000],
            "stderr": proc.stderr[:12000],
            "duration_ms": int((time.time() - start) * 1000),
        }, args=args)
    except subprocess.TimeoutExpired as exc:
        return enrich_run_result({
            "ok": False,
            "args": args,
            "exit_code": -1,
            "stdout": (exc.stdout or "")[:12000],
            "stderr": f"Timeout after {timeout_s}s",
            "duration_ms": int((time.time() - start) * 1000),
        }, args=args)


def _format_plan_output(result: dict) -> str:
    return format_plan_output_generic(result=result, tool_name="chainsaw")


def build_chainsaw_plan_dict(evtx_dir: str, execute: bool = False, timeout_s: int = 300) -> dict:
    tools_dir = _get_windows_tools_dir()
    exe_path = tools_dir / "chainsaw" / "chainsaw.exe"
    tool = _find_binary([exe_path])
    if not tool:
        return {
            "ok": False,
            "tool": "chainsaw",
            "error": "chainsaw.exe not found",
            "searched_paths": [str(exe_path)],
        }

    args = [str(tool), "hunt", str(Path(evtx_dir).resolve())]
    result = {
        "ok": True,
        "tool": "chainsaw",
        "mode": "plan_only",
        "execute": execute,
        "args": args,
        "notes": "Rules and output options are deferred.",
    }
    if execute:
        result["run_result"] = _run_command(args=args, timeout_s=timeout_s)
    return result


@function_tool
def build_chainsaw_plan(evtx_dir: str, execute: bool = False, timeout_s: int = 300) -> str:
    return _format_plan_output(
        build_chainsaw_plan_dict(evtx_dir=evtx_dir, execute=execute, timeout_s=timeout_s)
    )