"""
EntitlementJail CLI helpers.

This module provides structured wrappers around the entitlement-jail CLI,
including `xpc run` probe execution, matrix group runs, and evidence bundling.
It normalizes stdout/stderr into a consistent record and preserves enough
metadata to correlate observer output with probes.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from book.api import path_utils
from book.api.entitlementjail.logging import (
    LOG_OBSERVER_LAST,
    extract_correlation_id,
    extract_details,
    extract_process_name,
    extract_service_pid,
    observer_status,
    run_sandbox_log_observer,
    should_run_observer,
)
from book.api.entitlementjail.paths import EJ, REPO_ROOT
from book.api.profile_tools.identity import baseline_world_id

# Used to tag outputs with the fixed baseline world id.
WORLD_ID = baseline_world_id(REPO_ROOT)


def write_json(path: Path, payload: Dict[str, object]) -> None:
    # Keep experiment outputs deterministic and newline-terminated.
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n")
    print(f"[+] wrote {path_utils.to_repo_relative(path, REPO_ROOT)}")


def run_cmd(cmd: List[str], *, cwd: Optional[Path] = None) -> Dict[str, object]:
    """Run a CLI command and return a structured result for logs/reports."""
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, cwd=str(cwd) if cwd else str(REPO_ROOT))
        return {
            "command": path_utils.relativize_command(cmd, REPO_ROOT),
            "exit_code": res.returncode,
            "stdout": res.stdout,
            "stderr": res.stderr,
        }
    except Exception as exc:
        return {
            "command": path_utils.relativize_command(cmd, REPO_ROOT),
            "error": f"{type(exc).__name__}: {exc}",
        }


def copy_file(src: Path, dest: Path) -> Optional[str]:
    # EntitlementJail writes logs under app-managed paths; copy into the repo.
    if not src.exists():
        return f"source_missing: {src}"
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
    except Exception as exc:
        return f"{type(exc).__name__}: {exc}"
    return None


def copy_tree(src: Path, dest: Path) -> Optional[str]:
    # Used for matrix/evidence outputs that are emitted outside the repo.
    if not src.exists():
        return f"source_missing: {src}"
    dest.mkdir(parents=True, exist_ok=True)
    try:
        for path in src.iterdir():
            if path.is_dir():
                shutil.copytree(path, dest / path.name, dirs_exist_ok=True)
            else:
                shutil.copy2(path, dest / path.name)
    except Exception as exc:
        return f"{type(exc).__name__}: {exc}"
    return None


def home_hint(path: Path) -> str:
    # Preserve a human-readable hint without baking in an absolute repo path.
    home = Path.home()
    try:
        rel = path.relative_to(home)
        return f"$HOME/{rel}"
    except Exception:
        return str(path)


def resolve_first_existing(candidates: Iterable[Path]) -> Path:
    # Prefer the actual output location when the app is sandboxed.
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return next(iter(candidates))


def maybe_parse_json(text: str) -> Optional[Dict[str, object]]:
    # EntitlementJail generally returns JSON, but stderr/stdout can be non-JSON on error.
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        return None


def extract_profile_bundle_id(stdout_json: Optional[Dict[str, object]]) -> Optional[str]:
    # show-profile/describe-service outputs embed bundle ids under data.profile.
    if not isinstance(stdout_json, dict):
        return None
    data = stdout_json.get("data")
    if isinstance(data, dict):
        profile = data.get("profile")
        if isinstance(profile, dict):
            bundle_id = profile.get("bundle_id")
            if isinstance(bundle_id, str):
                return bundle_id
    return None


def extract_tmp_dir(stdout_json: Optional[Dict[str, object]]) -> Optional[str]:
    # tmp_dir is recorded in data.details for probes that create temp paths.
    details = extract_details(stdout_json)
    if details is None:
        return None
    tmp_dir = details.get("tmp_dir")
    return tmp_dir if isinstance(tmp_dir, str) else None


def extract_file_path(stdout_json: Optional[Dict[str, object]]) -> Optional[str]:
    # file_path is used for follow-on probes (xattr, rename, etc.).
    details = extract_details(stdout_json)
    if details is None:
        return None
    file_path = details.get("file_path")
    return file_path if isinstance(file_path, str) else None


def extract_stdout_text(stdout_json: Optional[Dict[str, object]]) -> Optional[str]:
    # Probe stdout is often nested under result.stdout in the JSON response.
    if not isinstance(stdout_json, dict):
        return None
    result = stdout_json.get("result")
    if isinstance(result, dict):
        value = result.get("stdout")
        if isinstance(value, str) and value:
            return value
    value = stdout_json.get("stdout")
    if isinstance(value, str) and value:
        return value
    return None


def parse_probe_catalog(stdout_json: Optional[Dict[str, object]]) -> Optional[List[str]]:
    """Extract probe ids from the probe_catalog stdout JSON payload."""
    payload_text = extract_stdout_text(stdout_json)
    if not payload_text:
        return None
    try:
        payload = json.loads(payload_text)
    except Exception:
        return None
    probes = payload.get("probes") if isinstance(payload, dict) else None
    if not isinstance(probes, list):
        return None
    out: List[str] = []
    for probe in probes:
        if isinstance(probe, dict):
            probe_id = probe.get("probe_id")
            if isinstance(probe_id, str):
                out.append(probe_id)
    return out


def run_xpc(
    *,
    profile_id: Optional[str] = None,
    service_id: Optional[str] = None,
    probe_id: str,
    probe_args: Sequence[str] = (),
    log_path: Optional[Path] = None,
    plan_id: str,
    row_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
    ack_risk: Optional[str] = None,
) -> Dict[str, object]:
    """Run a probe under a profile/service, capturing observer output when configured."""
    if (profile_id is None) == (service_id is None):
        raise ValueError("Provide exactly one of profile_id or service_id")
    cmd = [str(EJ), "xpc", "run"]
    if ack_risk:
        # Tier-2 profiles require an explicit acknowledgement token.
        cmd += ["--ack-risk", ack_risk]

    cmd += ["--plan-id", plan_id]
    if row_id:
        cmd += ["--row-id", row_id]
    if correlation_id:
        cmd += ["--correlation-id", correlation_id]
    if profile_id is not None:
        cmd += ["--profile", profile_id]
    else:
        # Caller can target a specific XPC bundle id instead of a profile.
        cmd += ["--service", service_id]
    cmd += [probe_id, *probe_args]
    started_at_unix_s = time.time()
    res = run_cmd(cmd)
    finished_at_unix_s = time.time()

    stdout_text = res.get("stdout", "").strip()
    stdout_json = maybe_parse_json(stdout_text)
    log_write_error = None
    if log_path is not None and stdout_text:
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_path.write_text(stdout_text + "\n")
        except Exception as exc:
            log_write_error = f"{type(exc).__name__}: {exc}"

    observer: Optional[Dict[str, object]] = None
    observer_log_path = None
    if log_path is not None and should_run_observer():
        observer_dest = log_path.parent / "observer" / f"{log_path.name}.observer.json"
        observer_log_path = path_utils.to_repo_relative(observer_dest, REPO_ROOT)
        observer_correlation_id = extract_correlation_id(stdout_json) or correlation_id
        observer = run_sandbox_log_observer(
            pid=extract_service_pid(stdout_json),
            process_name=extract_process_name(stdout_json),
            dest_path=observer_dest,
            last=LOG_OBSERVER_LAST,
            start_s=started_at_unix_s,
            end_s=finished_at_unix_s,
            plan_id=plan_id,
            row_id=row_id,
            correlation_id=observer_correlation_id,
        )

    record: Dict[str, object] = {
        "profile_id": profile_id,
        "service_id": service_id,
        "probe_id": probe_id,
        "probe_args": list(probe_args),
        "plan_id": plan_id,
        "row_id": row_id,
        "correlation_id": correlation_id,
        "started_at_unix_s": started_at_unix_s,
        "finished_at_unix_s": finished_at_unix_s,
        "duration_s": finished_at_unix_s - started_at_unix_s,
        "log_path": path_utils.to_repo_relative(log_path, REPO_ROOT) if log_path else None,
        "observer": observer,
        "observer_log_path": observer_log_path,
        "observer_status": observer_status(observer),
        "log_write_error": log_write_error,
        **res,
    }
    if stdout_text:
        if stdout_json is not None:
            record["stdout_json"] = stdout_json
        else:
            record["stdout_json_error"] = "stdout_not_json"
    else:
        record["stdout_json_error"] = "stdout_empty"
    return record


def run_matrix_group(group: str, *, ack_risk: Optional[str], dest_dir: Path) -> Dict[str, object]:
    """Run a matrix group and write outputs into the repo."""
    if dest_dir.exists():
        shutil.rmtree(dest_dir, ignore_errors=True)
    cmd = [str(EJ), "run-matrix", "--group", group, "--out", str(dest_dir), "capabilities_snapshot"]
    if ack_risk:
        cmd += ["--ack-risk", ack_risk]
    res = run_cmd(cmd)
    return {
        "world_id": WORLD_ID,
        "entrypoint": path_utils.to_repo_relative(EJ, REPO_ROOT),
        "group": group,
        "out_dir": path_utils.to_repo_relative(dest_dir, REPO_ROOT),
        **res,
    }


def bundle_evidence(*, ack_risk: Optional[str], dest_dir: Path) -> Dict[str, object]:
    """Create a bundle-evidence snapshot and write outputs into the repo."""
    if dest_dir.exists():
        shutil.rmtree(dest_dir, ignore_errors=True)
    cmd = [str(EJ), "bundle-evidence", "--out", str(dest_dir), "--include-health-check"]
    if ack_risk:
        cmd += ["--ack-risk", ack_risk]
    res = run_cmd(cmd)
    return {
        "world_id": WORLD_ID,
        "entrypoint": path_utils.to_repo_relative(EJ, REPO_ROOT),
        "out_dir": path_utils.to_repo_relative(dest_dir, REPO_ROOT),
        **res,
    }
