"""
Apply-preflight helpers for runtime plan execution.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional

from book.api import path_utils
from book.api.runtime.contracts import schema as rt_contract


REPO_ROOT = path_utils.find_repo_root(Path(__file__))


def sandbox_check_self() -> Dict[str, Any]:
    info: Dict[str, Any] = {"source": "sandbox_check"}
    try:
        lib_path = ctypes.util.find_library("system_sandbox")
        if not lib_path:
            raise RuntimeError("libsystem_sandbox not found")
        lib = ctypes.CDLL(lib_path)
        fn = lib.sandbox_check
        fn.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
        fn.restype = ctypes.c_int
        rc = fn(os.getpid(), None, 0)
        info.update({"rc": int(rc), "sandboxed": bool(rc == 1)})
    except Exception as exc:
        info["error"] = str(exc)
    return info


def run_apply_preflight(
    *,
    world_id: str,
    profile_path: Path,
    runner_path: Path,
) -> Dict[str, Any]:
    run_id = os.environ.get("SANDBOX_LORE_RUN_ID")
    record: Dict[str, Any] = {
        "world_id": world_id,
        "run_id": run_id,
        "profile": path_utils.to_repo_relative(profile_path, repo_root=REPO_ROOT),
        "runner": path_utils.to_repo_relative(runner_path, repo_root=REPO_ROOT),
        "sandbox_check_self": sandbox_check_self(),
    }
    if not profile_path.exists():
        record["status"] = "error"
        record["error"] = "missing_preflight_profile"
        return record
    if not runner_path.exists():
        record["status"] = "error"
        record["error"] = "missing_sandbox_runner"
        return record
    cmd = [str(runner_path), str(profile_path), "--", "/usr/bin/true"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        stderr = res.stderr or ""
        apply_markers = rt_contract.extract_sbpl_apply_markers(stderr)
        apply_report = rt_contract.derive_apply_report_from_markers(apply_markers) if apply_markers else None
        record.update(
            {
                "status": "ok",
                "command": path_utils.relativize_command(cmd, repo_root=REPO_ROOT),
                "exit_code": res.returncode,
                "stdout": res.stdout,
                "stderr": rt_contract.strip_tool_markers(stderr),
                "apply_report": apply_report,
                "apply_marker_pid": (apply_markers[0].get("pid") if apply_markers else None),
                "apply_ok": bool(apply_report and apply_report.get("rc") == 0),
                "failure_stage": "apply" if apply_report and apply_report.get("rc") not in (0, None) else None,
            }
        )
    except subprocess.TimeoutExpired:
        record["status"] = "error"
        record["error"] = "timeout"
    except Exception as exc:
        record["status"] = "error"
        record["error"] = str(exc)
    return record
