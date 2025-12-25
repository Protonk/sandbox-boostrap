"""EntitlementJail CLI helpers for entitlement-diff."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from book.api import path_utils
from book.api.profile_tools.identity import baseline_world_id


REPO_ROOT = path_utils.find_repo_root(Path(__file__))
WORLD_ID = baseline_world_id(REPO_ROOT)
EJ = REPO_ROOT / "book" / "tools" / "entitlement" / "EntitlementJail.app" / "Contents" / "MacOS" / "entitlement-jail"
LOG_OBSERVER = (
    REPO_ROOT
    / "book"
    / "tools"
    / "entitlement"
    / "EntitlementJail.app"
    / "Contents"
    / "MacOS"
    / "sandbox-log-observer"
)

LOG_CAPTURE_MODE = os.environ.get("EJ_LOG_MODE", "stream").lower()
LOG_OBSERVER_MODE = os.environ.get("EJ_LOG_OBSERVER", "fallback").lower()
LOG_OBSERVER_LAST = os.environ.get("EJ_LOG_LAST", "10s")

MATRIX_SOURCE_CANDIDATES = (
    Path.home()
    / "Library"
    / "Containers"
    / "com.yourteam.entitlement-jail"
    / "Data"
    / "Library"
    / "Application Support"
    / "entitlement-jail"
    / "matrix"
    / "latest",
    Path.home() / "Library" / "Application Support" / "entitlement-jail" / "matrix" / "latest",
)

EVIDENCE_SOURCE_CANDIDATES = (
    Path.home()
    / "Library"
    / "Containers"
    / "com.yourteam.entitlement-jail"
    / "Data"
    / "Library"
    / "Application Support"
    / "entitlement-jail"
    / "evidence"
    / "latest",
    Path.home() / "Library" / "Application Support" / "entitlement-jail" / "evidence" / "latest",
)


def _safe_tag(tag: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in tag)


def _log_capture_args(log_path: Path) -> Tuple[str, List[str], Optional[str]]:
    mode = LOG_CAPTURE_MODE
    if mode == "sandbox":
        return "sandbox", ["--log-sandbox", str(log_path)], None
    if mode == "path_class":
        log_name = _safe_tag(log_path.name)
        return "path_class", ["--log-path-class", "tmp", "--log-name", log_name], log_name
    return "stream", ["--log-stream", str(log_path)], None


def write_json(path: Path, payload: Dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n")
    print(f"[+] wrote {path_utils.to_repo_relative(path, REPO_ROOT)}")


def run_cmd(cmd: List[str], *, cwd: Optional[Path] = None) -> Dict[str, object]:
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
    if not src.exists():
        return f"source_missing: {src}"
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
    except Exception as exc:
        return f"{type(exc).__name__}: {exc}"
    return None


def copy_tree(src: Path, dest: Path) -> Optional[str]:
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
    home = Path.home()
    try:
        rel = path.relative_to(home)
        return f"$HOME/{rel}"
    except Exception:
        return str(path)


def resolve_first_existing(candidates: Iterable[Path]) -> Path:
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return next(iter(candidates))


def maybe_parse_json(text: str) -> Optional[Dict[str, object]]:
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        return None


def extract_details(stdout_json: Optional[Dict[str, object]]) -> Optional[Dict[str, object]]:
    if not isinstance(stdout_json, dict):
        return None
    data = stdout_json.get("data")
    if isinstance(data, dict):
        details = data.get("details")
        if isinstance(details, dict):
            return details
    details = stdout_json.get("details")
    if isinstance(details, dict):
        return details
    return None


def extract_log_capture_path(stdout_json: Optional[Dict[str, object]]) -> Optional[str]:
    if not isinstance(stdout_json, dict):
        return None
    data = stdout_json.get("data")
    if isinstance(data, dict):
        log_path = data.get("log_capture_path")
        if isinstance(log_path, str):
            return log_path
    return None


def extract_log_capture_status(stdout_json: Optional[Dict[str, object]]) -> Optional[str]:
    if not isinstance(stdout_json, dict):
        return None
    data = stdout_json.get("data")
    if isinstance(data, dict):
        status = data.get("log_capture_status")
        if isinstance(status, str):
            return status
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
    for key in ("service_pid", "probe_pid", "pid"):
        value = details.get(key)
        if isinstance(value, int):
            return str(value)
        if isinstance(value, str) and value:
            return value
    return None


def extract_profile_bundle_id(stdout_json: Optional[Dict[str, object]]) -> Optional[str]:
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
    details = extract_details(stdout_json)
    if details is None:
        return None
    tmp_dir = details.get("tmp_dir")
    return tmp_dir if isinstance(tmp_dir, str) else None


def extract_file_path(stdout_json: Optional[Dict[str, object]]) -> Optional[str]:
    details = extract_details(stdout_json)
    if details is None:
        return None
    file_path = details.get("file_path")
    return file_path if isinstance(file_path, str) else None


def extract_stdout_text(stdout_json: Optional[Dict[str, object]]) -> Optional[str]:
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


def _should_run_observer(stdout_json: Optional[Dict[str, object]]) -> bool:
    if LOG_OBSERVER_MODE == "disabled":
        return False
    if LOG_OBSERVER_MODE == "always":
        return True
    status = extract_log_capture_status(stdout_json)
    if status is None:
        return True
    return status != "captured"


def run_sandbox_log_observer(
    *,
    pid: Optional[str],
    process_name: Optional[str],
    dest_path: Path,
    last: str,
) -> Dict[str, object]:
    if pid is None or process_name is None:
        return {"skipped": "missing_pid_or_process_name"}
    if not LOG_OBSERVER.exists():
        return {
            "skipped": "observer_missing",
            "observer_path": path_utils.to_repo_relative(LOG_OBSERVER, REPO_ROOT),
        }

    cmd = [str(LOG_OBSERVER), "--pid", str(pid), "--process-name", process_name, "--last", last]
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
        "stdout_bytes": len(res.stdout),
    }


def run_xpc(
    *,
    profile_id: str,
    service_id: str,
    probe_id: str,
    probe_args: Sequence[str],
    log_path: Optional[Path],
    plan_id: str,
    row_id: str,
    ack_risk: Optional[str],
    use_profile: bool = True,
) -> Dict[str, object]:
    cmd = [str(EJ), "run-xpc"]
    if ack_risk:
        cmd += ["--ack-risk", ack_risk]

    capture_path: Optional[Path] = None
    log_copy_error: Optional[str] = None
    log_capture_mode: Optional[str] = None
    log_capture_log_name: Optional[str] = None
    if log_path is not None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        if log_path.exists():
            log_path.unlink()
        log_capture_mode, log_args, log_name = _log_capture_args(log_path)
        log_capture_log_name = log_name
        cmd += log_args

    cmd += ["--plan-id", plan_id, "--row-id", row_id]
    if use_profile:
        cmd += ["--profile", profile_id]
    else:
        cmd.append(service_id)
    cmd += [probe_id, *probe_args]
    res = run_cmd(cmd)

    stdout_text = res.get("stdout", "").strip()
    stdout_json = maybe_parse_json(stdout_text)
    if log_path is not None:
        capture_source = extract_log_capture_path(stdout_json)
        if capture_source:
            capture_path = Path(capture_source)
        if capture_path is None and log_path.exists():
            capture_path = log_path
        if capture_path and capture_path != log_path:
            log_copy_error = copy_file(capture_path, log_path)
        elif log_path.exists():
            log_copy_error = None
        else:
            log_copy_error = "log_capture_path_missing"

    observer: Optional[Dict[str, object]] = None
    if log_path is not None and _should_run_observer(stdout_json):
        observer = run_sandbox_log_observer(
            pid=extract_service_pid(stdout_json),
            process_name=extract_process_name(stdout_json),
            dest_path=log_path.parent / "observer" / log_path.name,
            last=LOG_OBSERVER_LAST,
        )

    record: Dict[str, object] = {
        "profile_id": profile_id,
        "service_id": service_id,
        "probe_id": probe_id,
        "probe_args": list(probe_args),
        "plan_id": plan_id,
        "row_id": row_id,
        "log_capture_mode": log_capture_mode,
        "log_capture_log_name": log_capture_log_name,
        "log_path": path_utils.to_repo_relative(log_path, REPO_ROOT) if log_path else None,
        "log_capture_source": home_hint(capture_path) if capture_path else None,
        "log_copy_error": log_copy_error,
        "observer": observer,
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
    cmd = [str(EJ), "run-matrix", "--group", group, "capabilities_snapshot"]
    if ack_risk:
        cmd += ["--ack-risk", ack_risk]
    res = run_cmd(cmd)
    source_dir = resolve_first_existing(MATRIX_SOURCE_CANDIDATES)
    copy_error = copy_tree(source_dir, dest_dir)
    return {
        "world_id": WORLD_ID,
        "entrypoint": path_utils.to_repo_relative(EJ, REPO_ROOT),
        "group": group,
        "out_dir": path_utils.to_repo_relative(dest_dir, REPO_ROOT),
        "source_out_dir_hint": home_hint(source_dir),
        "source_candidates": [home_hint(candidate) for candidate in MATRIX_SOURCE_CANDIDATES],
        "copy_error": copy_error,
        **res,
    }


def bundle_evidence(*, ack_risk: Optional[str], dest_dir: Path) -> Dict[str, object]:
    cmd = [str(EJ), "bundle-evidence", "--include-health-check"]
    if ack_risk:
        cmd += ["--ack-risk", ack_risk]
    res = run_cmd(cmd)
    source_dir = resolve_first_existing(EVIDENCE_SOURCE_CANDIDATES)
    copy_error = copy_tree(source_dir, dest_dir)
    return {
        "world_id": WORLD_ID,
        "entrypoint": path_utils.to_repo_relative(EJ, REPO_ROOT),
        "out_dir": path_utils.to_repo_relative(dest_dir, REPO_ROOT),
        "source_out_dir_hint": home_hint(source_dir),
        "source_candidates": [home_hint(candidate) for candidate in EVIDENCE_SOURCE_CANDIDATES],
        "copy_error": copy_error,
        **res,
    }
