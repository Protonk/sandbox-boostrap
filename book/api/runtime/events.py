"""
Canonical runtime observation schema and helpers for scenario identity.

This module does not execute probes; it normalizes harness output
(`runtime_results.json` + `expected_matrix.json`) into a single observation
shape with stable scenario IDs keyed to this world's runtime work. Full event
logs are treated as recomputable; callers can write small curated slices when
needed, but the normalization helpers are the source of truth.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional

from book.api import path_utils
from book.api.runtime import contract as rt_contract

# Fixed world for this repository.
WORLD_ID = "sonoma-14.4.1-23E224-arm64-dyld-2c0602c5"


@dataclass
class RuntimeObservation:
    """
    Canonical per-event runtime record for this world.

    Fields are intentionally redundant with the harness output so that a single
    observation carries enough context to stand alone or to be joined back to
    expectations and static mappings.
    """

    world_id: str
    profile_id: str
    scenario_id: str
    expectation_id: Optional[str] = None
    operation: str = ""
    target: Optional[str] = None
    probe_name: Optional[str] = None
    expected: Optional[str] = None
    actual: Optional[str] = None
    match: Optional[bool] = None
    runtime_status: Optional[str] = None
    errno: Optional[int] = None
    errno_name: Optional[str] = None
    failure_stage: Optional[str] = None
    failure_kind: Optional[str] = None
    apply_report: Optional[Dict[str, Any]] = None
    preflight: Optional[Dict[str, Any]] = None
    runner_info: Optional[Dict[str, Any]] = None
    seatbelt_callouts: Optional[List[Dict[str, Any]]] = None
    entitlement_checks: Optional[List[Dict[str, Any]]] = None
    violation_summary: Optional[str] = None
    command: Optional[List[str]] = None
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    harness: Optional[str] = None
    notes: Optional[str] = None


def _strip_sbpl_apply_markers(stderr: Optional[str]) -> Optional[str]:
    """
    Remove tool JSONL markers from stderr.

    Tool markers are inputs to normalization/classification, not part of the
    canonical normalized runtime IR payload.
    """
    return rt_contract.strip_tool_markers(stderr)


def _validate_probe_contract(
    runtime_result: Mapping[str, Any],
    stderr_raw: Optional[str],
) -> None:
    """
    Guardrail invariants enforced at the normalization boundary.

    These protect downstream mappings/reports from regressing back into ad-hoc
    stderr inference or accidental over-attribution.
    """

    sbpl_markers = rt_contract.extract_sbpl_apply_markers(stderr_raw)
    seatbelt_markers = rt_contract.extract_seatbelt_callout_markers(stderr_raw)
    entitlement_markers = rt_contract.extract_entitlement_check_markers(stderr_raw)

    rr_ver = runtime_result.get("runtime_result_schema_version", 0)
    if rr_ver not in rt_contract.SUPPORTED_RUNTIME_RESULT_SCHEMA_VERSIONS:
        raise AssertionError(f"unsupported runtime_result_schema_version: {rr_ver}")
    marker_ver = runtime_result.get("tool_marker_schema_version", 0)
    if marker_ver not in rt_contract.SUPPORTED_TOOL_MARKER_SCHEMA_VERSIONS:
        raise AssertionError(f"unsupported tool_marker_schema_version: {marker_ver}")

    for marker in sbpl_markers:
        ver = marker.get("marker_schema_version", 0)
        if ver not in rt_contract.SUPPORTED_SBPL_APPLY_MARKER_SCHEMA_VERSIONS:
            raise AssertionError(f"unsupported sbpl-apply marker_schema_version: {ver}")
    for marker in seatbelt_markers:
        ver = marker.get("marker_schema_version", 0)
        if ver not in rt_contract.SUPPORTED_SEATBELT_CALLOUT_MARKER_SCHEMA_VERSIONS:
            raise AssertionError(f"unsupported seatbelt-callout marker_schema_version: {ver}")
    for marker in entitlement_markers:
        ver = marker.get("marker_schema_version", 0)
        if ver not in rt_contract.SUPPORTED_ENTITLEMENT_CHECK_MARKER_SCHEMA_VERSIONS:
            raise AssertionError(f"unsupported entitlement-check marker_schema_version: {ver}")

    stages = [m.get("stage") for m in sbpl_markers]
    if "applied" in stages and "apply" not in stages:
        raise AssertionError("sbpl-apply marker order violation: applied without apply")
    if "exec" in stages and "apply" not in stages:
        raise AssertionError("sbpl-apply marker order violation: exec without apply")
    if "exec" in stages and "applied" not in stages:
        raise AssertionError("sbpl-apply marker order violation: exec without applied")

    apply_report = runtime_result.get("apply_report")
    if sbpl_markers and apply_report is None:
        raise AssertionError("apply markers present but apply_report missing")
    if isinstance(apply_report, dict):
        if apply_report.get("err_class") is None or apply_report.get("err_class_source") is None:
            raise AssertionError("apply_report missing err_class or err_class_source")

    failure_stage = runtime_result.get("failure_stage")
    if failure_stage == "apply" and isinstance(apply_report, dict):
        if apply_report.get("rc") == 0:
            raise AssertionError("failure_stage=apply but apply_report.rc==0")
        if "applied" in stages or "exec" in stages:
            raise AssertionError("failure_stage=apply but later sbpl-apply markers present")
    if failure_stage == "bootstrap" and isinstance(apply_report, dict):
        if apply_report.get("rc") not in (0, None):
            raise AssertionError("failure_stage=bootstrap but apply_report.rc!=0")
        if sbpl_markers and ("applied" not in stages or "exec" not in stages):
            raise AssertionError("failure_stage=bootstrap but missing applied/exec markers")

    runner_info = runtime_result.get("runner_info")
    if isinstance(runner_info, dict):
        entry_sha = runner_info.get("entrypoint_sha256")
        tool_build = runner_info.get("tool_build_id")
        if isinstance(entry_sha, str):
            if tool_build is None:
                raise AssertionError("runner_info missing tool_build_id")
            if tool_build != entry_sha:
                raise AssertionError("runner_info.tool_build_id does not match entrypoint_sha256")

def derive_expectation_id(profile_id: str, operation: Optional[str], target: Optional[str]) -> str:
    """
    Fallback expectation identifier when one is not present in the matrix.

    Mirrors the provisional pattern described in runtime_log_schema.v0.1.json:
    profile_id|op|path. Keeps simple separators to avoid collisions.
    """

    op_part = operation or "op"
    target_part = target or "target"
    return "|".join([profile_id, op_part, target_part])


def make_scenario_id(
    world_id: str,
    profile_id: str,
    probe_name: Optional[str] = None,
    expectation_id: Optional[str] = None,
    operation: Optional[str] = None,
    target: Optional[str] = None,
) -> str:
    """
    Build a stable scenario_id for runtime traces.

    Priority:
    1. If expectation_id exists, reuse it (most stable link to expectations).
    2. Else, use profile_id + probe_name when available.
    3. Else, fall back to profile_id + op + target.
    World is carried separately; do not bake it into the ID.
    """

    if expectation_id:
        return expectation_id
    if probe_name:
        return f"{profile_id}::{probe_name}"
    op_part = operation or "op"
    target_part = target or "target"
    return f"{profile_id}::{op_part}::{target_part}"


def serialize_observation(obs: RuntimeObservation) -> Dict[str, Any]:
    """
    Serialize an observation to a JSON-friendly dict, dropping None values.
    """

    raw = asdict(obs)
    return {k: v for k, v in raw.items() if v is not None}


def _index_expectations(matrix: Mapping[str, Any]) -> Dict[str, Dict[str, Any]]:
    """
    Build lookup map: profile_id -> probe_name -> expectation record.
    """

    profiles = matrix.get("profiles") or {}
    idx: Dict[str, Dict[str, Any]] = {}
    for profile_id, rec in profiles.items():
        probes = rec.get("probes") or []
        by_name: Dict[str, Any] = {}
        for probe in probes:
            name = probe.get("name")
            if not name:
                continue
            by_name[name] = probe
        idx[profile_id] = by_name
    return idx


def _expectation_for(
    expectations_index: Mapping[str, Mapping[str, Any]],
    profile_id: str,
    probe_name: Optional[str],
) -> Dict[str, Any]:
    return (expectations_index.get(profile_id) or {}).get(probe_name or "", {}) or {}


def normalize_runtime_results(
    expected_matrix: Mapping[str, Any],
    runtime_results: Mapping[str, Any],
    world_id: Optional[str] = None,
    harness_version: Optional[str] = None,
) -> List[RuntimeObservation]:
    """
    Normalize harness output into RuntimeObservation rows.

    expected_matrix: full parsed expected_matrix.json.
    runtime_results: full parsed runtime_results.json.
    world_id: overrides the world id to stamp on observations (defaults to WORLD_ID).
    harness_version: optional string to tag the harness build/revision.
    """

    resolved_world = world_id or expected_matrix.get("world_id") or runtime_results.get("world_id") or WORLD_ID
    expectations_idx = _index_expectations(expected_matrix or {})

    observations: List[RuntimeObservation] = []
    for profile_id, profile_result in (runtime_results or {}).items():
        preflight = profile_result.get("preflight")
        probes = profile_result.get("probes") or []
        for probe in probes:
            probe_name = probe.get("name")
            expectation_rec = _expectation_for(expectations_idx, profile_id, probe_name)
            op = probe.get("operation") or expectation_rec.get("operation")
            target = probe.get("path") or probe.get("target") or expectation_rec.get("target")
            expectation_id = probe.get("expectation_id") or expectation_rec.get("expectation_id")
            expectation_id = expectation_id or derive_expectation_id(profile_id, op, target)
            scenario_id = make_scenario_id(
                resolved_world,
                profile_id,
                probe_name=probe_name or expectation_rec.get("name"),
                expectation_id=expectation_id,
                operation=op,
                target=target,
            )
            expected_decision = probe.get("expected") or expectation_rec.get("expected")
            actual_decision = probe.get("actual")
            match = probe.get("match")
            stderr_raw = probe.get("stderr")
            runtime_result = rt_contract.upgrade_runtime_result(probe.get("runtime_result") or {}, stderr_raw)
            if runtime_result.get("failure_stage") is None and runtime_result.get("status") != "success":
                runtime_result["failure_stage"] = "probe"
                runtime_result.setdefault("failure_kind", "probe_errno")
            _validate_probe_contract(runtime_result, stderr_raw)
            apply_report = runtime_result.get("apply_report")
            stderr_canonical = _strip_sbpl_apply_markers(stderr_raw)
            rt_contract.assert_no_tool_markers_in_stderr(stderr_canonical)

            observations.append(
                RuntimeObservation(
                    world_id=resolved_world,
                    profile_id=profile_id,
                    scenario_id=scenario_id,
                    expectation_id=expectation_id,
                    operation=op or "",
                    target=target,
                    probe_name=probe_name or expectation_rec.get("name"),
                    expected=expected_decision,
                    actual=actual_decision,
                    match=match,
                    runtime_status=runtime_result.get("status"),
                    errno=runtime_result.get("errno"),
                    errno_name=None,
                    failure_stage=runtime_result.get("failure_stage"),
                    failure_kind=runtime_result.get("failure_kind"),
                    apply_report=apply_report,
                    preflight=preflight if isinstance(preflight, Mapping) else None,
                    runner_info=runtime_result.get("runner_info"),
                    seatbelt_callouts=runtime_result.get("seatbelt_callouts"),
                    entitlement_checks=runtime_result.get("entitlement_checks"),
                    violation_summary=probe.get("violation_summary"),
                    command=probe.get("command"),
                    stdout=probe.get("stdout"),
                    stderr=stderr_canonical,
                    harness=harness_version,
                    notes=probe.get("notes"),
                )
            )
    return observations


def load_json(path: Path | str) -> Any:
    """
    Read a JSON file with repo-relative resolution.
    """

    abs_path = path_utils.ensure_absolute(Path(path), path_utils.find_repo_root(Path(__file__)))
    with abs_path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def write_observations(observations: Iterable[RuntimeObservation], out_path: Path | str) -> Path:
    """
    Write observations as a JSON array to the given path.
    """

    path = path_utils.ensure_absolute(Path(out_path), path_utils.find_repo_root(Path(__file__)))
    payload = [serialize_observation(o) for o in observations]
    path.parent.mkdir(parents=True, exist_ok=True)
    import json

    path.write_text(json.dumps(payload, indent=2, sort_keys=True))
    return path


def normalize_from_paths(
    expected_matrix_path: Path | str,
    runtime_results_path: Path | str,
    world_id: Optional[str] = None,
    harness_version: Optional[str] = None,
) -> List[RuntimeObservation]:
    """
    Load expected_matrix + runtime_results from disk and return normalized observations.
    """

    expected_doc = load_json(expected_matrix_path)
    runtime_doc = load_json(runtime_results_path)
    return normalize_runtime_results(expected_doc, runtime_doc, world_id=world_id, harness_version=harness_version)


def write_normalized_events(
    expected_matrix_path: Path | str,
    runtime_results_path: Path | str,
    out_path: Path | str,
    world_id: Optional[str] = None,
    harness_version: Optional[str] = None,
) -> Path:
    """
    Normalize events from disk and write them as a JSON array.
    """

    observations = normalize_from_paths(expected_matrix_path, runtime_results_path, world_id=world_id, harness_version=harness_version)
    return write_observations(observations, out_path)


def normalize_metadata_runner_results(
    runtime_results: Mapping[str, Any],
    world_id: Optional[str] = None,
    harness_version: Optional[str] = None,
    runner_info: Optional[Mapping[str, Any]] = None,
) -> List[RuntimeObservation]:
    """
    Normalize metadata-runner experiment output into RuntimeObservation rows.

    metadata-runner emits a bespoke runtime_results.json shape:
    - {world_id, runner_info?, results:[{profile_id, operation, requested_path, status, errno, apply_mode, apply_rc, ...}]}
    """

    resolved_world = world_id or runtime_results.get("world_id") or WORLD_ID
    base_runner_info: Optional[Dict[str, Any]] = None
    if isinstance(runner_info, Mapping):
        base_runner_info = dict(runner_info)
    elif isinstance(runtime_results.get("runner_info"), Mapping):
        base_runner_info = dict(runtime_results.get("runner_info") or {})

    rows = runtime_results.get("results") or []
    if not isinstance(rows, list):
        raise AssertionError("metadata-runner runtime_results.json should contain a results list")

    observations: List[RuntimeObservation] = []
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        profile_id = str(row.get("profile_id") or "")
        if not profile_id:
            continue

        op = row.get("operation") or row.get("op") or ""
        op = str(op) if op is not None else ""
        target = row.get("requested_path") or row.get("path")
        target = str(target) if target is not None else None

        syscall = row.get("syscall")
        attr_payload = row.get("attr_payload")
        probe_name: Optional[str] = None
        if syscall:
            probe_name = str(syscall)
            if attr_payload:
                probe_name = f"{probe_name}:{attr_payload}"

        expectation_id = derive_expectation_id(profile_id, op, target)
        if syscall or attr_payload:
            expectation_id = "|".join([expectation_id, str(syscall or "syscall"), str(attr_payload or "payload")])

        scenario_id = make_scenario_id(
            resolved_world,
            profile_id,
            probe_name=probe_name,
            expectation_id=expectation_id,
            operation=op,
            target=target,
        )

        stderr_raw = row.get("stderr") or ""
        if not isinstance(stderr_raw, str):
            stderr_raw = str(stderr_raw)

        sbpl_markers = rt_contract.extract_sbpl_apply_markers(stderr_raw)
        seatbelt_markers = rt_contract.extract_seatbelt_callout_markers(stderr_raw)

        apply_report = rt_contract.derive_apply_report_from_markers(sbpl_markers) if sbpl_markers else None
        if apply_report is None:
            apply_mode = row.get("apply_mode")
            apply_rc = row.get("apply_rc")
            api = None
            if apply_mode == "sbpl":
                api = "sandbox_init"
            elif apply_mode == "blob":
                api = "sandbox_apply"
            if api and isinstance(apply_rc, int):
                err = row.get("apply_errno") if isinstance(row.get("apply_errno"), int) else (0 if apply_rc == 0 else None)
                errbuf = row.get("apply_errbuf") if isinstance(row.get("apply_errbuf"), str) else None
                err_class, source = rt_contract.classify_apply_err_class(api, apply_rc, err, errbuf)
                apply_report = {
                    "api": api,
                    "rc": apply_rc,
                    "errno": err,
                    "errbuf": errbuf,
                    "err_class": err_class,
                    "err_class_source": source,
                }

        status = row.get("status")
        runtime_status = "success" if status == "ok" else "errno"
        syscall_errno = row.get("errno") if isinstance(row.get("errno"), int) else None
        observed_errno = None if status == "ok" else syscall_errno

        failure_stage: Optional[str] = None
        failure_kind: Optional[str] = None
        if isinstance(apply_report, dict) and isinstance(apply_report.get("rc"), int) and apply_report.get("rc") != 0:
            failure_stage = "apply"
            api = apply_report.get("api")
            err_class = apply_report.get("err_class")
            if err_class == "already_sandboxed":
                failure_kind = "apply_already_sandboxed"
            else:
                failure_kind = f"{api}_failed" if isinstance(api, str) and api else "apply_failed"
            observed_errno = apply_report.get("errno") if isinstance(apply_report.get("errno"), int) else observed_errno
        elif status != "ok":
            failure_stage = "probe"
            failure_kind = "probe_syscall_errno"

        actual = "allow" if status == "ok" else "deny"
        violation_summary = "EPERM" if (status != "ok" and observed_errno == 1) else None

        runtime_result = {
            "status": runtime_status,
            "errno": observed_errno,
            "runtime_result_schema_version": rt_contract.CURRENT_RUNTIME_RESULT_SCHEMA_VERSION,
            "tool_marker_schema_version": rt_contract.CURRENT_TOOL_MARKER_SCHEMA_VERSION,
            "failure_stage": failure_stage,
            "failure_kind": failure_kind,
            "apply_report": apply_report,
            "runner_info": base_runner_info,
            "seatbelt_callouts": seatbelt_markers or None,
        }

        _validate_probe_contract(runtime_result, stderr_raw)
        stderr_canonical = _strip_sbpl_apply_markers(stderr_raw)
        rt_contract.assert_no_tool_markers_in_stderr(stderr_canonical)

        notes_parts: List[str] = []
        if probe_name:
            notes_parts.append(f"probe={probe_name}")
        msg = row.get("message")
        if isinstance(msg, str) and msg:
            notes_parts.append(f"message={msg}")
        notes = "; ".join(notes_parts) if notes_parts else None

        observations.append(
            RuntimeObservation(
                world_id=resolved_world,
                profile_id=profile_id,
                scenario_id=scenario_id,
                expectation_id=expectation_id,
                operation=op,
                target=target,
                probe_name=probe_name,
                expected=None,
                actual=actual,
                match=None,
                runtime_status=runtime_status,
                errno=observed_errno,
                errno_name=str(row.get("errno_name")) if isinstance(row.get("errno_name"), str) else None,
                failure_stage=failure_stage,
                failure_kind=failure_kind,
                apply_report=apply_report,
                runner_info=base_runner_info,
                seatbelt_callouts=seatbelt_markers or None,
                violation_summary=violation_summary,
                command=None,
                stdout=None,
                stderr=stderr_canonical,
                harness=harness_version or "metadata-runner",
                notes=notes,
            )
        )

    return observations


def write_metadata_runner_normalized_events(
    runtime_results_path: Path | str,
    out_path: Path | str,
    world_id: Optional[str] = None,
    harness_version: Optional[str] = None,
    runner_info: Optional[Mapping[str, Any]] = None,
) -> Path:
    runtime_doc = load_json(runtime_results_path)
    observations = normalize_metadata_runner_results(runtime_doc, world_id=world_id, harness_version=harness_version, runner_info=runner_info)
    return write_observations(observations, out_path)
