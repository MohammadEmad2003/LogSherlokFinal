from __future__ import annotations

import csv
import datetime
import gzip
import hashlib
import json
import logging
import os
import re
import sqlite3
import tarfile
import xml.etree.ElementTree as ET
from io import StringIO
from pathlib import Path
from typing import Any

LOGGER = logging.getLogger(__name__)

_IOC_PATTERNS = {
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "url": re.compile(r"https?://[^\s\"'<>]+"),
    "base64_like": re.compile(r"\b(?:[A-Za-z0-9+/]{20,}={0,2})\b"),
}


def _extract_iocs(text: str) -> dict[str, list[str]]:
    iocs: dict[str, list[str]] = {}
    for key, pattern in _IOC_PATTERNS.items():
        values = sorted(set(pattern.findall(text)))
        if values:
            iocs[key] = values[:25]
    return iocs


def _csv_preview(text: str, max_rows: int = 5) -> list[list[str]]:
    if not text or "," not in text:
        return []
    try:
        reader = csv.reader(StringIO(text))
        rows: list[list[str]] = []
        for i, row in enumerate(reader):
            rows.append(row)
            if i + 1 >= max_rows:
                break
        # Basic sanity check so plain text does not look like CSV accidentally.
        if len(rows) >= 2 and len(rows[0]) >= 2:
            return rows
    except Exception:
        return []
    return []


def _xml_info(text: str) -> dict[str, Any] | None:
    if not text:
        return None
    stripped = text.lstrip()
    if not stripped.startswith("<"):
        return None
    try:
        root = ET.fromstring(stripped)
        children = [child.tag for child in list(root)[:10]]
        return {"root_tag": root.tag, "child_tags": children}
    except Exception:
        return None


def _artifact_hints(args: list[str]) -> list[str]:
    hints: list[str] = []
    for raw in args:
        path = Path(raw)
        if not path.exists() or path.is_dir():
            continue

        suffixes = [s.lower() for s in path.suffixes]

        try:
            if tarfile.is_tarfile(path):
                with tarfile.open(path) as tf:
                    hints.append(f"tar_entries={len(tf.getmembers())} path={path}")
                continue
        except Exception:
            pass

        if path.suffix.lower() in {".gz", ".gzip", ".tgz"}:
            try:
                with gzip.open(path, "rb") as gf:
                    head = gf.read(32)
                hints.append(f"gzip_detected path={path} head_hex={head.hex()[:32]}")
            except Exception:
                hints.append(f"gzip_detected path={path} (read_failed)")

        if any(s in {".db", ".sqlite", ".sqlite3"} for s in suffixes):
            try:
                with sqlite3.connect(path) as conn:
                    cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
                    tables = [row[0] for row in cur.fetchall()]
                hints.append(f"sqlite_tables={len(tables)} path={path}")
            except Exception:
                hints.append(f"sqlite_detected path={path} (read_failed)")

    return hints


def enrich_run_result(run_result: dict[str, Any], args: list[str]) -> dict[str, Any]:
    enriched = dict(run_result)
    stdout = enriched.get("stdout", "") or ""
    stderr = enriched.get("stderr", "") or ""
    combined = f"{stdout}\n{stderr}"

    enriched["timestamp_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    enriched["stdout_sha256"] = hashlib.sha256(stdout.encode("utf-8", "replace")).hexdigest()
    enriched["iocs"] = _extract_iocs(combined)

    csv_rows = _csv_preview(stdout)
    if csv_rows:
        enriched["csv_preview"] = csv_rows

    xml_meta = _xml_info(stdout)
    if xml_meta:
        enriched["xml_info"] = xml_meta

    hints = _artifact_hints(args)
    if hints:
        enriched["artifact_hints"] = hints

    LOGGER.info(
        "forensics_tool_run",
        extra={
            "tool_args": " ".join(args[:6]),
            "ok": enriched.get("ok"),
            "exit_code": enriched.get("exit_code"),
            "duration_ms": enriched.get("duration_ms"),
        },
    )

    return enriched


def format_plan_output_generic(result: dict[str, Any], tool_name: str) -> str:
    output_mode = os.getenv("CAI_FORENSICS_OUTPUT_MODE", "text").lower().strip()
    if output_mode == "json":
        payload = dict(result)
        payload.setdefault("tool", tool_name)
        return json.dumps(payload, ensure_ascii=False, default=str)

    if not result.get("ok"):
        searched = result.get("searched_paths", [])
        searched_text = "\n".join(f"- {p}" for p in searched) if searched else "- (none)"
        return (
            "Status: error\n"
            f"Tool: {tool_name}\n"
            f"Message: {result.get('error', 'unknown error')}\n"
            f"Searched paths:\n{searched_text}"
        )

    lines = [
        "Status: ok",
        f"Tool: {tool_name}",
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
                f"- timestamp_utc: {run_result.get('timestamp_utc', '')}",
                f"- stdout_sha256: {run_result.get('stdout_sha256', '')}",
                f"- stdout: {run_result.get('stdout', '').strip() or '(empty)'}",
                f"- stderr: {run_result.get('stderr', '').strip() or '(empty)'}",
            ]
        )

        iocs = run_result.get("iocs", {})
        if iocs:
            lines.append(f"- iocs: {json.dumps(iocs, ensure_ascii=False)}")

        csv_preview = run_result.get("csv_preview")
        if csv_preview:
            lines.append(f"- csv_preview_rows: {len(csv_preview)}")

        xml_info = run_result.get("xml_info")
        if xml_info:
            lines.append(f"- xml_info: {json.dumps(xml_info, ensure_ascii=False)}")

        hints = run_result.get("artifact_hints")
        if hints:
            lines.append(f"- artifact_hints: {json.dumps(hints, ensure_ascii=False)}")

    return "\n".join(lines)
