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
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from book.api import exec_record, path_utils, tooling
from book.api.runtime.bundles import writer as bundle_writer
from book.api.runtime.execution import service as runtime_service
from book.api.profile.identity import baseline_world_id
from book.api.witness import outputs
from book.api.witness.analysis import lifecycle
from book.api.witness.models import ProbeRequest, ProbeResult
from .observer import (
    OBSERVER_LAST,
    extract_correlation_id,
    extract_process_name,
    extract_service_pid,
    observer_status,
    run_sandbox_log_observer,
    should_run_observer,
)
from book.api.witness.paths import (
    REPO_ROOT,
    WITNESS_CLI,
    WITNESS_EVIDENCE_MANIFEST,
    WITNESS_EVIDENCE_PROFILES,
    WITNESS_EVIDENCE_SYMBOLS,
)

# Used to tag outputs with the fixed baseline world id.
WORLD_ID = baseline_world_id(REPO_ROOT)


def _witness_runner_info() -> Dict[str, object]:
    return tooling.runner_info(WITNESS_CLI, repo_root=REPO_ROOT, entrypoint="policy-witness")


def extract_profile_bundle_id(
    stdout_json: Optional[Dict[str, object]],
    *,
    variant: Optional[str] = None,
) -> Optional[str]:
    # show-profile outputs embed bundle ids under data.profile.variants[*].
    if not isinstance(stdout_json, dict):
        return None
    data = stdout_json.get("data")
    if not isinstance(data, dict):
        return None
    profile = data.get("profile")
    if not isinstance(profile, dict):
        return None

    bundle_id = profile.get("bundle_id")
    if isinstance(bundle_id, str):
        return bundle_id

    variants = profile.get("variants")
    if not isinstance(variants, list):
        return None

    preferred_variant = variant or "base"
    fallback_bundle_id = None
    for entry in variants:
        if not isinstance(entry, dict):
            continue
        entry_bundle_id = entry.get("bundle_id")
        if not isinstance(entry_bundle_id, str):
            continue
        if entry.get("variant") == preferred_variant:
            return entry_bundle_id
        if fallback_bundle_id is None:
            fallback_bundle_id = entry_bundle_id
    return fallback_bundle_id


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


def list_profiles(*, timeout_s: Optional[float] = None) -> Dict[str, object]:
    record = exec_record.run_json_command([str(WITNESS_CLI), "list-profiles"], timeout_s=timeout_s, repo_root=REPO_ROOT)
    return {
        "world_id": WORLD_ID,
        "entrypoint": path_utils.to_repo_relative(WITNESS_CLI, REPO_ROOT),
        "runner_info": _witness_runner_info(),
        **record,
    }


def list_services(*, timeout_s: Optional[float] = None) -> Dict[str, object]:
    record = exec_record.run_json_command([str(WITNESS_CLI), "list-services"], timeout_s=timeout_s, repo_root=REPO_ROOT)
    _normalize_data_path(record.get("stdout_json"), "profiles_path")
    return {
        "world_id": WORLD_ID,
        "entrypoint": path_utils.to_repo_relative(WITNESS_CLI, REPO_ROOT),
        "runner_info": _witness_runner_info(),
        **record,
    }


def show_profile(profile_id: str, *, timeout_s: Optional[float] = None) -> Dict[str, object]:
    record = exec_record.run_json_command(
        [str(WITNESS_CLI), "show-profile", profile_id],
        timeout_s=timeout_s,
        repo_root=REPO_ROOT,
    )
    _normalize_data_path(record.get("stdout_json"), "profiles_path")
    return {
        "world_id": WORLD_ID,
        "entrypoint": path_utils.to_repo_relative(WITNESS_CLI, REPO_ROOT),
        "runner_info": _witness_runner_info(),
        "profile_id": profile_id,
        **record,
    }


def describe_service(profile_id: str, *, timeout_s: Optional[float] = None) -> Dict[str, object]:
    record = exec_record.run_json_command(
        [str(WITNESS_CLI), "describe-service", profile_id],
        timeout_s=timeout_s,
        repo_root=REPO_ROOT,
    )
    return {
        "world_id": WORLD_ID,
        "entrypoint": path_utils.to_repo_relative(WITNESS_CLI, REPO_ROOT),
        "runner_info": _witness_runner_info(),
        "profile_id": profile_id,
        **record,
    }


def health_check(*, profile_id: Optional[str] = None, timeout_s: Optional[float] = None) -> Dict[str, object]:
    cmd = [str(WITNESS_CLI), "health-check"]
    if profile_id:
        cmd += ["--profile", profile_id]
    record = exec_record.run_json_command(cmd, timeout_s=timeout_s, repo_root=REPO_ROOT)
    _normalize_data_path(record.get("stdout_json"), "profiles_path")
    payload: Dict[str, object] = {
        "world_id": WORLD_ID,
        "entrypoint": path_utils.to_repo_relative(WITNESS_CLI, REPO_ROOT),
        "runner_info": _witness_runner_info(),
    }
    if profile_id:
        payload["profile_id"] = profile_id
    return {**payload, **record}


def verify_evidence(*, timeout_s: Optional[float] = None) -> Dict[str, object]:
    record = exec_record.run_json_command([str(WITNESS_CLI), "verify-evidence"], timeout_s=timeout_s, repo_root=REPO_ROOT)
    _normalize_data_path(record.get("stdout_json"), "manifest_path")
    return {
        "world_id": WORLD_ID,
        "entrypoint": path_utils.to_repo_relative(WITNESS_CLI, REPO_ROOT),
        "runner_info": _witness_runner_info(),
        **record,
    }


def inspect_macho(selector: str, *, timeout_s: Optional[float] = None) -> Dict[str, object]:
    record = exec_record.run_json_command(
        [str(WITNESS_CLI), "inspect-macho", selector],
        timeout_s=timeout_s,
        repo_root=REPO_ROOT,
    )
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
        "entrypoint": path_utils.to_repo_relative(WITNESS_CLI, REPO_ROOT),
        "runner_info": _witness_runner_info(),
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
    cmd = [str(WITNESS_CLI), "run-matrix", "--group", group, "--out", str(dest_dir), probe_id, *probe_args]
    record = exec_record.run_json_command(cmd, timeout_s=timeout_s, repo_root=REPO_ROOT)
    _normalize_data_path(record.get("stdout_json"), "output_dir")
    return {
        "world_id": WORLD_ID,
        "entrypoint": path_utils.to_repo_relative(WITNESS_CLI, REPO_ROOT),
        "runner_info": _witness_runner_info(),
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
    variant: Optional[str] = None,
    bundle_id: Optional[str] = None,
) -> Dict[str, object]:
    show = None
    resolved_bundle_id = bundle_id
    if resolved_bundle_id is None:
        show = show_profile(profile_id, timeout_s=timeout_s)
        resolved_bundle_id = extract_profile_bundle_id(show.get("stdout_json"), variant=variant)
    payload: Dict[str, object] = {
        "world_id": WORLD_ID,
        "entrypoint": path_utils.to_repo_relative(WITNESS_CLI, REPO_ROOT),
        "runner_info": _witness_runner_info(),
        "profile_id": profile_id,
        "bundle_id": resolved_bundle_id,
        "show_profile": show,
    }
    if variant:
        payload["variant"] = variant
    if bundle_id:
        payload["bundle_id_override"] = bundle_id
    if not resolved_bundle_id:
        payload["error"] = "bundle_id_missing"
        return payload

    cmd = [str(WITNESS_CLI), "quarantine-lab", resolved_bundle_id, payload_class, *payload_args]
    record = exec_record.run_json_command(cmd, timeout_s=timeout_s, repo_root=REPO_ROOT)
    _normalize_data_path(record.get("stdout_json"), "output_dir")
    payload["run"] = record
    return payload


def load_evidence_manifest() -> Dict[str, object]:
    return {
        "path": path_utils.to_repo_relative(WITNESS_EVIDENCE_MANIFEST, REPO_ROOT),
        "data": json.loads(WITNESS_EVIDENCE_MANIFEST.read_text()),
    }


def load_evidence_profiles() -> Dict[str, object]:
    return {
        "path": path_utils.to_repo_relative(WITNESS_EVIDENCE_PROFILES, REPO_ROOT),
        "data": json.loads(WITNESS_EVIDENCE_PROFILES.read_text()),
    }


def load_evidence_symbols() -> Dict[str, object]:
    return {
        "path": path_utils.to_repo_relative(WITNESS_EVIDENCE_SYMBOLS, REPO_ROOT),
        "data": json.loads(WITNESS_EVIDENCE_SYMBOLS.read_text()),
    }


def run_probe_request(
    request: ProbeRequest,
    *,
    output: Optional[outputs.OutputSpec] = None,
    observer: bool = True,
) -> ProbeResult:
    """Run a probe under a profile/service, capturing observer output when configured."""
    request.validate()

    started_at_unix_s = time.time()
    probe_timeout_s = request.timeout_s or 25.0
    cmd = [str(WITNESS_CLI), "xpc", "run"]
    if request.profile_id:
        cmd += ["--profile", request.profile_id]
    elif request.service_id:
        cmd += ["--service", request.service_id]
    else:
        raise ValueError("profile_id or service_id is required for run_probe")
    cmd += ["--plan-id", request.plan_id]
    if request.row_id:
        cmd += ["--row-id", request.row_id]
    if request.correlation_id:
        cmd += ["--correlation-id", request.correlation_id]
    if request.capture_sandbox_logs:
        cmd += ["--capture-sandbox-logs"]
    cmd += [request.probe_id, *request.probe_args]

    bundle_root = None
    bundle_run_id = None
    effective_output = output
    if output is not None and output.bundle_root is not None:
        if output.out_dir or output.log_path or output.record_path or output.observer_path:
            raise ValueError("bundle_root is incompatible with explicit output paths")
        bundle_run_id = output.bundle_run_id or str(uuid.uuid4())
        bundle_root = path_utils.ensure_absolute(output.bundle_root, REPO_ROOT)
        bundle_dir = bundle_root / bundle_run_id
        effective_output = outputs.OutputSpec(
            out_dir=bundle_dir,
            prefix=output.prefix,
            write_stdout_json=output.write_stdout_json,
            write_record_json=output.write_record_json,
            json_indent=output.json_indent,
            json_sort_keys=output.json_sort_keys,
        )

    res = exec_record.run_command(cmd, timeout_s=probe_timeout_s, repo_root=REPO_ROOT)
    finished_at_unix_s = time.time()
    stdout_text = res.get("stdout", "")
    stderr_text = res.get("stderr", "")
    stdout_json = exec_record.maybe_parse_json(stdout_text)

    out_paths = outputs.resolve_output_paths(
        effective_output,
        plan_id=request.plan_id,
        row_id=request.row_id,
        probe_id=request.probe_id,
    )

    log_write_error = None
    if (
        effective_output is not None
        and effective_output.write_stdout_json
        and out_paths.log_path is not None
        and stdout_json is not None
    ):
        log_write_error = outputs.write_json(
            out_paths.log_path,
            stdout_json,
            indent=effective_output.json_indent,
            sort_keys=effective_output.json_sort_keys,
        )

    observer_record = None
    observer_log_path = None
    if observer and out_paths.observer_path is not None and stdout_json is not None and should_run_observer():
        observer_record = run_sandbox_log_observer(
            pid=extract_service_pid(stdout_json),
            process_name=extract_process_name(stdout_json),
            dest_path=out_paths.observer_path,
            last=OBSERVER_LAST,
            start_s=started_at_unix_s,
            end_s=finished_at_unix_s,
            plan_id=request.plan_id,
            row_id=request.row_id,
            correlation_id=extract_correlation_id(stdout_json) or request.correlation_id,
        )
        observer_log_path = path_utils.to_repo_relative(out_paths.observer_path, REPO_ROOT)

    probe_result = ProbeResult(
        world_id=WORLD_ID,
        entrypoint=path_utils.to_repo_relative(WITNESS_CLI, REPO_ROOT),
        profile_id=request.profile_id,
        service_id=request.service_id,
        probe_id=request.probe_id,
        probe_args=list(request.probe_args),
        plan_id=request.plan_id,
        row_id=request.row_id,
        correlation_id=request.correlation_id,
        capture_sandbox_logs=request.capture_sandbox_logs,
        started_at_unix_s=started_at_unix_s,
        finished_at_unix_s=finished_at_unix_s,
        duration_s=finished_at_unix_s - started_at_unix_s,
        command=res.get("command"),
        exit_code=res.get("exit_code"),
        stdout=stdout_text,
        stderr=stderr_text,
        log_path=path_utils.to_repo_relative(out_paths.log_path, REPO_ROOT) if out_paths.log_path else None,
        observer=observer_record,
        observer_log_path=observer_log_path,
        observer_status=observer_status(observer_record),
        probe_timeout_s=probe_timeout_s,
        probe_error=res.get("error"),
        runner_info=_witness_runner_info(),
        lifecycle=lifecycle.snapshot_from_probe(
            stdout_json,
            profile_id=request.profile_id,
            service_id=request.service_id,
            plan_id=request.plan_id,
            row_id=request.row_id,
        ),
        log_write_error=log_write_error,
    )
    if stdout_json is not None:
        probe_result.stdout_json = stdout_json
    else:
        probe_result.stdout_json_error = "stdout_json_missing"

    record_write_error = None
    if effective_output is not None and effective_output.write_record_json and out_paths.record_path is not None:
        record_write_error = outputs.write_json(
            out_paths.record_path,
            probe_result.to_json(),
            indent=effective_output.json_indent,
            sort_keys=effective_output.json_sort_keys,
        )
    probe_result.record_write_error = record_write_error

    if bundle_root is not None and bundle_run_id is not None and output is not None and output.bundle_write_index:
        expected = []
        for path in (out_paths.log_path, out_paths.record_path, out_paths.observer_path):
            if path is None:
                continue
            try:
                rel = path.relative_to(bundle_root / bundle_run_id)
            except ValueError:
                continue
            expected.append(str(rel))
        artifact_index = bundle_writer.write_artifact_index(
            bundle_root / bundle_run_id,
            run_id=bundle_run_id,
            world_id=WORLD_ID,
            schema_version=runtime_service.ARTIFACT_INDEX_SCHEMA_VERSION,
            expected_artifacts=expected,
            repo_root=REPO_ROOT,
        )
        probe_result.bundle = {
            "run_id": bundle_run_id,
            "bundle_root": path_utils.to_repo_relative(bundle_root, REPO_ROOT),
            "bundle_dir": path_utils.to_repo_relative(bundle_root / bundle_run_id, REPO_ROOT),
            "artifact_index": path_utils.to_repo_relative(artifact_index, REPO_ROOT),
            "schema_version": runtime_service.ARTIFACT_INDEX_SCHEMA_VERSION,
        }

    return probe_result


def run_probe(
    *,
    profile_id: Optional[str] = None,
    service_id: Optional[str] = None,
    probe_id: str,
    probe_args: Sequence[str] = (),
    plan_id: str = "witness:probe",
    row_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
    capture_sandbox_logs: bool = False,
    timeout_s: Optional[float] = None,
    output: Optional[outputs.OutputSpec] = None,
    observer: bool = True,
) -> ProbeResult:
    request = ProbeRequest(
        profile_id=profile_id,
        service_id=service_id,
        probe_id=probe_id,
        probe_args=probe_args,
        plan_id=plan_id,
        row_id=row_id,
        correlation_id=correlation_id,
        capture_sandbox_logs=capture_sandbox_logs,
        timeout_s=timeout_s,
    )
    return run_probe_request(request, output=output, observer=observer)


def run_matrix_group(group: str, *, dest_dir: Path) -> Dict[str, object]:
    """Run a matrix group and write outputs into the repo."""
    if dest_dir.exists():
        shutil.rmtree(dest_dir, ignore_errors=True)
    cmd = [str(WITNESS_CLI), "run-matrix", "--group", group, "--out", str(dest_dir), "capabilities_snapshot"]
    res = exec_record.run_command(cmd, repo_root=REPO_ROOT)
    return {
        "world_id": WORLD_ID,
        "entrypoint": path_utils.to_repo_relative(WITNESS_CLI, REPO_ROOT),
        "runner_info": _witness_runner_info(),
        "group": group,
        "out_dir": path_utils.to_repo_relative(dest_dir, REPO_ROOT),
        **res,
    }


def bundle_evidence(*, dest_dir: Path) -> Dict[str, object]:
    """Create a bundle-evidence snapshot and write outputs into the repo."""
    if dest_dir.exists():
        shutil.rmtree(dest_dir, ignore_errors=True)
    cmd = [str(WITNESS_CLI), "bundle-evidence", "--out", str(dest_dir), "--include-health-check"]
    res = exec_record.run_command(cmd, repo_root=REPO_ROOT)
    return {
        "world_id": WORLD_ID,
        "entrypoint": path_utils.to_repo_relative(WITNESS_CLI, REPO_ROOT),
        "runner_info": _witness_runner_info(),
        "out_dir": path_utils.to_repo_relative(dest_dir, REPO_ROOT),
        **res,
    }


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
