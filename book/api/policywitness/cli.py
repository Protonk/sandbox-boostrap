"""
PolicyWitness CLI helpers.

This module provides structured wrappers around the policy-witness CLI,
including one-shot probe execution, matrix group runs, and evidence bundling.
It normalizes stdout/stderr into a consistent record and preserves enough
metadata to correlate observer output with probes.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from book.api import path_utils
from book.api.policywitness.logging import (
    LOG_OBSERVER_LAST,
    extract_correlation_id,
    extract_details,
    extract_process_name,
    extract_service_pid,
    observer_status,
    run_sandbox_log_observer,
    should_run_observer,
)
from book.api.policywitness.paths import (
    PW,
    PW_EVIDENCE_MANIFEST,
    PW_EVIDENCE_PROFILES,
    PW_EVIDENCE_SYMBOLS,
    REPO_ROOT,
)
from book.api.profile.identity import baseline_world_id

# Used to tag outputs with the fixed baseline world id.
WORLD_ID = baseline_world_id(REPO_ROOT)


def write_json(path: Path, payload: Dict[str, object]) -> None:
    # Keep experiment outputs deterministic and newline-terminated.
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n")
    print(f"[+] wrote {path_utils.to_repo_relative(path, REPO_ROOT)}")


def run_cmd(
    cmd: List[str],
    *,
    cwd: Optional[Path] = None,
    timeout_s: Optional[float] = None,
) -> Dict[str, object]:
    """Run a CLI command and return a structured result for logs/reports."""
    started_at_unix_s = time.time()
    try:
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=str(cwd) if cwd else str(REPO_ROOT),
            timeout=timeout_s,
        )
        finished_at_unix_s = time.time()
        return {
            "command": path_utils.relativize_command(cmd, REPO_ROOT),
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
            "command": path_utils.relativize_command(cmd, REPO_ROOT),
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
            "command": path_utils.relativize_command(cmd, REPO_ROOT),
            "error": f"{type(exc).__name__}: {exc}",
            "timeout_s": timeout_s,
            "cmd_started_at_unix_s": started_at_unix_s,
            "cmd_finished_at_unix_s": finished_at_unix_s,
            "cmd_duration_s": finished_at_unix_s - started_at_unix_s,
        }


def maybe_parse_json(text: str) -> Optional[Dict[str, object]]:
    # PolicyWitness generally returns JSON, but stderr/stdout can be non-JSON on error.
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


def parse_probe_catalog(stdout_json: Optional[Dict[str, object]]) -> Optional[Dict[str, object]]:
    """Extract probe metadata + trace symbols from the probe_catalog stdout JSON payload."""
    payload_text = extract_stdout_text(stdout_json)
    if not payload_text:
        return None
    try:
        payload = json.loads(payload_text)
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None
    probes = payload.get("probes")
    trace_symbols = payload.get("trace_symbols")
    if not isinstance(probes, list):
        return None
    probe_ids: List[str] = []
    probe_metadata: List[Dict[str, object]] = []
    for probe in probes:
        if not isinstance(probe, dict):
            continue
        probe_metadata.append(probe)
        probe_id = probe.get("probe_id")
        if isinstance(probe_id, str):
            probe_ids.append(probe_id)
    trace_entries: List[Dict[str, object]] = []
    if isinstance(trace_symbols, list):
        for entry in trace_symbols:
            if isinstance(entry, dict):
                trace_entries.append(entry)
    return {
        "generated_at_iso8601": payload.get("generated_at_iso8601")
        if isinstance(payload.get("generated_at_iso8601"), str)
        else None,
        "schema_version": payload.get("schema_version") if isinstance(payload.get("schema_version"), int) else None,
        "probes": probe_metadata,
        "probe_ids": probe_ids,
        "trace_symbols": trace_entries,
    }


def _normalize_path_value(value: object) -> Optional[str]:
    if not isinstance(value, str):
        return None
    path = Path(value)
    if not path.is_absolute():
        return value
    return path_utils.to_repo_relative(path, REPO_ROOT)


def _normalize_data_path(stdout_json: Optional[Dict[str, object]], key: str) -> None:
    if not isinstance(stdout_json, dict):
        return
    data = stdout_json.get("data")
    if not isinstance(data, dict):
        return
    normalized = _normalize_path_value(data.get(key))
    if normalized is not None:
        data[key] = normalized


def _wrap_json_command(cmd: List[str], *, timeout_s: Optional[float] = None) -> Dict[str, object]:
    res = run_cmd(cmd, timeout_s=timeout_s)
    stdout_json = maybe_parse_json(res.get("stdout", ""))
    record: Dict[str, object] = {**res}
    if stdout_json is not None:
        record["stdout_json"] = stdout_json
    else:
        record["stdout_json_error"] = "stdout_json_missing"
    return record


def list_profiles(*, timeout_s: Optional[float] = None) -> Dict[str, object]:
    record = _wrap_json_command([str(PW), "list-profiles"], timeout_s=timeout_s)
    return {
        "world_id": WORLD_ID,
        "entrypoint": path_utils.to_repo_relative(PW, REPO_ROOT),
        **record,
    }


def list_services(*, timeout_s: Optional[float] = None) -> Dict[str, object]:
    record = _wrap_json_command([str(PW), "list-services"], timeout_s=timeout_s)
    _normalize_data_path(record.get("stdout_json"), "profiles_path")
    return {
        "world_id": WORLD_ID,
        "entrypoint": path_utils.to_repo_relative(PW, REPO_ROOT),
        **record,
    }


def show_profile(profile_id: str, *, timeout_s: Optional[float] = None) -> Dict[str, object]:
    record = _wrap_json_command([str(PW), "show-profile", profile_id], timeout_s=timeout_s)
    _normalize_data_path(record.get("stdout_json"), "profiles_path")
    return {
        "world_id": WORLD_ID,
        "entrypoint": path_utils.to_repo_relative(PW, REPO_ROOT),
        "profile_id": profile_id,
        **record,
    }


def describe_service(profile_id: str, *, timeout_s: Optional[float] = None) -> Dict[str, object]:
    record = _wrap_json_command([str(PW), "describe-service", profile_id], timeout_s=timeout_s)
    return {
        "world_id": WORLD_ID,
        "entrypoint": path_utils.to_repo_relative(PW, REPO_ROOT),
        "profile_id": profile_id,
        **record,
    }


def health_check(*, profile_id: Optional[str] = None, timeout_s: Optional[float] = None) -> Dict[str, object]:
    cmd = [str(PW), "health-check"]
    if profile_id:
        cmd += ["--profile", profile_id]
    record = _wrap_json_command(cmd, timeout_s=timeout_s)
    _normalize_data_path(record.get("stdout_json"), "profiles_path")
    payload: Dict[str, object] = {
        "world_id": WORLD_ID,
        "entrypoint": path_utils.to_repo_relative(PW, REPO_ROOT),
    }
    if profile_id:
        payload["profile_id"] = profile_id
    return {**payload, **record}


def verify_evidence(*, timeout_s: Optional[float] = None) -> Dict[str, object]:
    record = _wrap_json_command([str(PW), "verify-evidence"], timeout_s=timeout_s)
    _normalize_data_path(record.get("stdout_json"), "manifest_path")
    return {
        "world_id": WORLD_ID,
        "entrypoint": path_utils.to_repo_relative(PW, REPO_ROOT),
        **record,
    }


def inspect_macho(selector: str, *, timeout_s: Optional[float] = None) -> Dict[str, object]:
    record = _wrap_json_command([str(PW), "inspect-macho", selector], timeout_s=timeout_s)
    stdout_json = record.get("stdout_json")
    if isinstance(stdout_json, dict):
        data = stdout_json.get("data")
        if isinstance(data, dict):
            for key in ("app_root", "manifest_path"):
                normalized = _normalize_path_value(data.get(key))
                if normalized is not None:
                    data[key] = normalized
            entry = data.get("entry")
            if isinstance(entry, dict):
                normalized = _normalize_path_value(entry.get("abs_path"))
                if normalized is not None:
                    entry["abs_path"] = normalized
    return {
        "world_id": WORLD_ID,
        "entrypoint": path_utils.to_repo_relative(PW, REPO_ROOT),
        "selector": selector,
        **record,
    }


def run_matrix(
    group: str,
    *,
    probe_id: str,
    probe_args: Sequence[str] = (),
    dest_dir: Path,
    timeout_s: Optional[float] = None,
) -> Dict[str, object]:
    if dest_dir.exists():
        shutil.rmtree(dest_dir, ignore_errors=True)
    cmd = [str(PW), "run-matrix", "--group", group, "--out", str(dest_dir), probe_id, *probe_args]
    record = _wrap_json_command(cmd, timeout_s=timeout_s)
    _normalize_data_path(record.get("stdout_json"), "output_dir")
    return {
        "world_id": WORLD_ID,
        "entrypoint": path_utils.to_repo_relative(PW, REPO_ROOT),
        "group": group,
        "probe_id": probe_id,
        "probe_args": list(probe_args),
        "out_dir": path_utils.to_repo_relative(dest_dir, REPO_ROOT),
        **record,
    }


def quarantine_lab(
    *,
    profile_id: str,
    payload_class: str,
    payload_args: Sequence[str] = (),
    timeout_s: Optional[float] = None,
) -> Dict[str, object]:
    show = show_profile(profile_id, timeout_s=timeout_s)
    bundle_id = extract_profile_bundle_id(show.get("stdout_json"))
    payload: Dict[str, object] = {
        "world_id": WORLD_ID,
        "entrypoint": path_utils.to_repo_relative(PW, REPO_ROOT),
        "profile_id": profile_id,
        "bundle_id": bundle_id,
        "show_profile": show,
    }
    if not bundle_id:
        payload["error"] = "bundle_id_missing"
        return payload

    cmd = [str(PW), "quarantine-lab", bundle_id, payload_class, *payload_args]
    record = _wrap_json_command(cmd, timeout_s=timeout_s)
    _normalize_data_path(record.get("stdout_json"), "output_dir")
    payload["run"] = record
    return payload


def load_evidence_manifest() -> Dict[str, object]:
    return {
        "path": path_utils.to_repo_relative(PW_EVIDENCE_MANIFEST, REPO_ROOT),
        "data": json.loads(PW_EVIDENCE_MANIFEST.read_text()),
    }


def load_evidence_profiles() -> Dict[str, object]:
    return {
        "path": path_utils.to_repo_relative(PW_EVIDENCE_PROFILES, REPO_ROOT),
        "data": json.loads(PW_EVIDENCE_PROFILES.read_text()),
    }


def load_evidence_symbols() -> Dict[str, object]:
    return {
        "path": path_utils.to_repo_relative(PW_EVIDENCE_SYMBOLS, REPO_ROOT),
        "data": json.loads(PW_EVIDENCE_SYMBOLS.read_text()),
    }


def run_xpc(
    *,
    profile_id: Optional[str] = None,
    probe_id: str,
    probe_args: Sequence[str] = (),
    log_path: Optional[Path] = None,
    plan_id: str,
    row_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
    capture_sandbox_logs: bool = False,
    timeout_s: Optional[float] = None,
) -> Dict[str, object]:
    """Run a probe under a profile, capturing observer output when configured."""
    if not profile_id:
        raise ValueError("profile_id is required for run_xpc")

    started_at_unix_s = time.time()
    probe_timeout_s = timeout_s or 25.0
    cmd = [str(PW), "xpc", "run", "--profile", profile_id]
    cmd += ["--plan-id", plan_id]
    if row_id:
        cmd += ["--row-id", row_id]
    if correlation_id:
        cmd += ["--correlation-id", correlation_id]
    if capture_sandbox_logs:
        cmd += ["--capture-sandbox-logs"]
    cmd += [probe_id, *probe_args]

    res = run_cmd(cmd, timeout_s=probe_timeout_s)
    finished_at_unix_s = time.time()
    stdout_text = res.get("stdout", "")
    stderr_text = res.get("stderr", "")
    stdout_json = maybe_parse_json(stdout_text)

    log_write_error = None
    if log_path is not None and stdout_json is not None:
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_path.write_text(json.dumps(stdout_json) + "\n")
        except Exception as exc:
            log_write_error = f"{type(exc).__name__}: {exc}"

    observer = None
    observer_log_path = None
    if log_path is not None and should_run_observer():
        observer_dest = log_path.parent / "observer" / f"{log_path.name}.observer.json"
        observer = run_sandbox_log_observer(
            pid=extract_service_pid(stdout_json),
            process_name=extract_process_name(stdout_json),
            dest_path=observer_dest,
            last=LOG_OBSERVER_LAST,
            start_s=started_at_unix_s,
            end_s=finished_at_unix_s,
            plan_id=plan_id,
            row_id=row_id,
            correlation_id=extract_correlation_id(stdout_json) or correlation_id,
        )
        observer_log_path = path_utils.to_repo_relative(observer_dest, REPO_ROOT)

    record: Dict[str, object] = {
        "profile_id": profile_id,
        "probe_id": probe_id,
        "probe_args": list(probe_args),
        "plan_id": plan_id,
        "row_id": row_id,
        "correlation_id": correlation_id,
        "capture_sandbox_logs": capture_sandbox_logs,
        "started_at_unix_s": started_at_unix_s,
        "finished_at_unix_s": finished_at_unix_s,
        "duration_s": finished_at_unix_s - started_at_unix_s,
        "command": res.get("command"),
        "exit_code": res.get("exit_code"),
        "stdout": stdout_text,
        "stderr": stderr_text,
        "log_path": path_utils.to_repo_relative(log_path, REPO_ROOT) if log_path else None,
        "observer": observer,
        "observer_log_path": observer_log_path,
        "observer_status": observer_status(observer),
        "log_write_error": log_write_error,
        "probe_timeout_s": probe_timeout_s,
        "probe_error": res.get("error"),
    }
    if stdout_json is not None:
        record["stdout_json"] = stdout_json
    else:
        record["stdout_json_error"] = "stdout_json_missing"
    return record


def run_matrix_group(group: str, *, dest_dir: Path) -> Dict[str, object]:
    """Run a matrix group and write outputs into the repo."""
    if dest_dir.exists():
        shutil.rmtree(dest_dir, ignore_errors=True)
    cmd = [str(PW), "run-matrix", "--group", group, "--out", str(dest_dir), "capabilities_snapshot"]
    res = run_cmd(cmd)
    return {
        "world_id": WORLD_ID,
        "entrypoint": path_utils.to_repo_relative(PW, REPO_ROOT),
        "group": group,
        "out_dir": path_utils.to_repo_relative(dest_dir, REPO_ROOT),
        **res,
    }


def bundle_evidence(*, dest_dir: Path) -> Dict[str, object]:
    """Create a bundle-evidence snapshot and write outputs into the repo."""
    if dest_dir.exists():
        shutil.rmtree(dest_dir, ignore_errors=True)
    cmd = [str(PW), "bundle-evidence", "--out", str(dest_dir), "--include-health-check"]
    res = run_cmd(cmd)
    return {
        "world_id": WORLD_ID,
        "entrypoint": path_utils.to_repo_relative(PW, REPO_ROOT),
        "out_dir": path_utils.to_repo_relative(dest_dir, REPO_ROOT),
        **res,
    }
