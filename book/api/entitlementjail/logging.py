"""
Logging and observer helpers for EntitlementJail probes.

EntitlementJail v2 decouples probe execution (`entitlement-jail xpc ...`) from
deny-evidence capture (`sandbox-log-observer`). This module:

- extracts PID/process identity from probe/session JSON, and
- runs the external observer (outside the sandbox boundary) with a stable
  time window policy.
"""

from __future__ import annotations

import datetime as dt
import os
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from book.api import path_utils
from book.api.entitlementjail.paths import LOG_OBSERVER, REPO_ROOT

# Environment-driven toggles for observer behavior.
#
# v1 supported embedded observer capture inside `run-xpc`; v2 runs the observer
# out-of-process only. Keep the env var for compatibility.
LOG_OBSERVER_MODE = os.environ.get("EJ_LOG_OBSERVER", "external").lower()
if LOG_OBSERVER_MODE == "embedded":
    LOG_OBSERVER_MODE = "external"
LOG_OBSERVER_LAST = os.environ.get("EJ_LOG_LAST", "10s")

try:
    LOG_OBSERVER_PAD_S = float(os.environ.get("EJ_LOG_PAD_S", "2.0"))
except Exception:
    LOG_OBSERVER_PAD_S = 2.0


def extract_details(stdout_json: Optional[Dict[str, object]]) -> Optional[Dict[str, object]]:
    if not isinstance(stdout_json, dict):
        return None
    data = stdout_json.get("data")
    if isinstance(data, dict):
        details = data.get("details")
        if isinstance(details, dict):
            return details
    # Older shapes sometimes included details at the top-level.
    details = stdout_json.get("details")
    if isinstance(details, dict):
        return details
    return None


def extract_process_name(stdout_json: Optional[Dict[str, object]]) -> Optional[str]:
    details = extract_details(stdout_json)
    if details is None:
        return None
    process_name = details.get("process_name")
    return process_name if isinstance(process_name, str) else None


def extract_service_pid(stdout_json: Optional[Dict[str, object]]) -> Optional[str]:
    details = extract_details(stdout_json)
    if details is None:
        return None
    # Prefer service_pid when present; fall back to probe_pid/pid for older outputs.
    for key in ("service_pid", "probe_pid", "pid"):
        value = details.get(key)
        if isinstance(value, int):
            return str(value)
        if isinstance(value, str) and value:
            return value
    return None


def extract_correlation_id(stdout_json: Optional[Dict[str, object]]) -> Optional[str]:
    details = extract_details(stdout_json)
    if details is None:
        return None
    correlation_id = details.get("correlation_id")
    return correlation_id if isinstance(correlation_id, str) else None


def should_run_observer() -> bool:
    """Return True when the external observer should be invoked."""
    return LOG_OBSERVER_MODE not in {"disabled", "off", "0"}


def observer_status(observer: Optional[Dict[str, object]]) -> str:
    # Keep a compact status field for experiment records.
    if observer is None:
        return "not_requested"
    skipped = observer.get("skipped")
    if skipped:
        return f"skipped:{skipped}"
    if observer.get("exit_code") == 0:
        return "ok"
    return "error"


def _format_time(ts: float) -> str:
    # Unified log time flags expect a local timestamp string.
    return dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def _observer_time_args(
    start_s: Optional[float],
    end_s: Optional[float],
    last: str,
) -> Tuple[List[str], Dict[str, object]]:
    # Use a padded window around the probe run when timestamps are available.
    if start_s is None or end_s is None:
        return ["--last", last], {
            "observer_window_mode": "last",
            "observer_window_last": last,
        }
    start = start_s - LOG_OBSERVER_PAD_S
    end = end_s + LOG_OBSERVER_PAD_S
    start_str = _format_time(start)
    end_str = _format_time(end)
    return ["--start", start_str, "--end", end_str], {
        "observer_window_mode": "range",
        "observer_window_start": start_str,
        "observer_window_end": end_str,
        "observer_window_pad_s": LOG_OBSERVER_PAD_S,
    }


def run_sandbox_log_observer(
    *,
    pid: Optional[str],
    process_name: Optional[str],
    dest_path: Path,
    last: str,
    start_s: Optional[float] = None,
    end_s: Optional[float] = None,
    plan_id: Optional[str] = None,
    row_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
) -> Dict[str, object]:
    """Run the external observer and persist its raw JSON output."""
    if pid is None or process_name is None:
        return {"skipped": "missing_pid_or_process_name"}
    if not LOG_OBSERVER.exists():
        return {
            "skipped": "observer_missing",
            "observer_path": path_utils.to_repo_relative(LOG_OBSERVER, REPO_ROOT),
        }

    # The observer uses unified logging outside the sandbox, with PID/name scoping.
    time_args, window_meta = _observer_time_args(start_s, end_s, last)
    cmd = [str(LOG_OBSERVER), "--pid", str(pid), "--process-name", process_name, *time_args]
    if plan_id:
        cmd += ["--plan-id", plan_id]
    if row_id:
        cmd += ["--row-id", row_id]
    if correlation_id:
        cmd += ["--correlation-id", correlation_id]

    try:
        res = subprocess.run(cmd, capture_output=True, text=True, cwd=str(REPO_ROOT))
    except Exception as exc:
        return {
            "command": path_utils.relativize_command(cmd, REPO_ROOT),
            "error": f"{type(exc).__name__}: {exc}",
        }

    dest_path.parent.mkdir(parents=True, exist_ok=True)
    write_error = None
    try:
        dest_path.write_text(res.stdout)
    except Exception as exc:
        write_error = f"{type(exc).__name__}: {exc}"

    return {
        "command": path_utils.relativize_command(cmd, REPO_ROOT),
        "exit_code": res.returncode,
        "stderr": res.stderr,
        "log_path": path_utils.to_repo_relative(dest_path, REPO_ROOT),
        "log_write_error": write_error,
        "pid": str(pid),
        "process_name": process_name,
        "last": last,
        "plan_id": plan_id,
        "row_id": row_id,
        "correlation_id": correlation_id,
        "stdout_bytes": len(res.stdout),
        **window_meta,
    }
