"""Shared command execution record helpers."""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from typing import Dict, Optional, Sequence

from book.api import path_utils


def maybe_parse_json(text: str) -> Optional[Dict[str, object]]:
    if not text:
        return None
    try:
        payload = json.loads(text)
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def run_command(
    cmd: Sequence[str],
    *,
    cwd: Optional[Path] = None,
    timeout_s: Optional[float] = None,
    repo_root: Optional[Path] = None,
) -> Dict[str, object]:
    repo_root = repo_root or path_utils.find_repo_root(Path(__file__))
    started_at_unix_s = time.time()
    try:
        res = subprocess.run(
            list(cmd),
            capture_output=True,
            text=True,
            cwd=str(cwd) if cwd else str(repo_root),
            timeout=timeout_s,
        )
        finished_at_unix_s = time.time()
        return {
            "command": path_utils.relativize_command(cmd, repo_root),
            "exit_code": res.returncode,
            "stdout": res.stdout,
            "stderr": res.stderr,
            "timeout_s": timeout_s,
            "cmd_started_at_unix_s": started_at_unix_s,
            "cmd_finished_at_unix_s": finished_at_unix_s,
            "cmd_duration_s": finished_at_unix_s - started_at_unix_s,
        }
    except subprocess.TimeoutExpired as exc:
        finished_at_unix_s = time.time()
        return {
            "command": path_utils.relativize_command(cmd, repo_root),
            "exit_code": None,
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or "",
            "error": "timeout",
            "timed_out": True,
            "timeout_s": timeout_s,
            "cmd_started_at_unix_s": started_at_unix_s,
            "cmd_finished_at_unix_s": finished_at_unix_s,
            "cmd_duration_s": finished_at_unix_s - started_at_unix_s,
        }
    except Exception as exc:
        finished_at_unix_s = time.time()
        return {
            "command": path_utils.relativize_command(cmd, repo_root),
            "exit_code": None,
            "stdout": "",
            "stderr": "",
            "error": f"{type(exc).__name__}: {exc}",
            "timeout_s": timeout_s,
            "cmd_started_at_unix_s": started_at_unix_s,
            "cmd_finished_at_unix_s": finished_at_unix_s,
            "cmd_duration_s": finished_at_unix_s - started_at_unix_s,
        }


def run_json_command(
    cmd: Sequence[str],
    *,
    cwd: Optional[Path] = None,
    timeout_s: Optional[float] = None,
    repo_root: Optional[Path] = None,
) -> Dict[str, object]:
    record = run_command(cmd, cwd=cwd, timeout_s=timeout_s, repo_root=repo_root)
    stdout_json = maybe_parse_json(record.get("stdout", ""))
    if stdout_json is not None:
        record["stdout_json"] = stdout_json
    else:
        record["stdout_json_error"] = "stdout_json_missing"
    return record
