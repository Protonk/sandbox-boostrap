"""
Canonical runtime observation schema and helpers for scenario identity.

This module does not execute probes; it normalizes harness output
(`runtime_results.json` + `expected_matrix.json`) into a single observation
shape with stable scenario IDs keyed to this world's runtime work. Full event
logs are treated as recomputable; callers can write small curated slices when
needed, but the normalization helpers are the source of truth.

Normalization is the bridge between noisy execution and durable
evidence. Once normalized, observations can be compared across runs without
relearning every probe's quirks.
"""

from __future__ import annotations

from dataclasses import asdict
import errno
import json
import os
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional

from book.api import path_utils
from book.api.runtime.contracts import schema as rt_contract
from book.api.runtime.contracts import models

# Host-bound alias map derived from vfs-canonicalization (partial).
# Keep this small; full canonicalization mappings live in generated artifacts.
_PATH_ALIAS_PREFIXES = (
    ("/tmp", "/private/tmp"),
)


def _strip_sbpl_apply_markers(stderr: Optional[str]) -> Optional[str]:
    """
    Remove tool JSONL markers from stderr.

    Tool markers are inputs to normalization/classification, not part of the
    canonical normalized runtime IR payload.
    """
    return rt_contract.strip_tool_markers(stderr)

def _extract_path_observation(stderr: Optional[str]) -> Dict[str, Optional[str]]:
    if not stderr:
        return {"path": None, "source": "not_attempted"}
    for line in stderr.splitlines():
        if line.startswith("F_GETPATH:"):
            return {"path": line.split(":", 1)[1].strip() or None, "source": "fd_path"}
        if line.startswith("F_GETPATH_ERROR:"):
            return {"path": None, "source": "error"}
        if line.startswith("F_GETPATH_UNAVAILABLE"):
            return {"path": None, "source": "unavailable"}
    return {"path": None, "source": "not_attempted"}

def _probe_path_observation(probe: Mapping[str, Any]) -> Dict[str, Optional[str]]:
    path_obs = probe.get("path_observation")
    if not isinstance(path_obs, Mapping):
        return {"path": None, "source": None}
    path = path_obs.get("observed_path") or path_obs.get("path")
    source = path_obs.get("observed_path_source") or path_obs.get("source")
    return {"path": path, "source": source}


def _normalize_path(requested: Optional[str], observed: Optional[str]) -> Dict[str, Optional[str]]:
    if observed:
        return {"path": observed, "source": "observed_path"}
    if not requested:
        return {"path": None, "source": None}
    for prefix, replacement in _PATH_ALIAS_PREFIXES:
        if requested == prefix:
            return {"path": replacement, "source": "alias_map"}
        if requested.startswith(prefix + "/"):
            return {"path": replacement + requested[len(prefix):], "source": "alias_map"}
    return {"path": requested, "source": "requested_path"}


def _is_path_operation(op: Optional[str]) -> bool:
    if not op:
        return False
    return op.startswith("file-") or op in {"file-read*", "file-write*", "file-read-data", "file-write-data"}


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
    preflight_markers = rt_contract.extract_sbpl_preflight_markers(stderr_raw)
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
    for marker in preflight_markers:
        ver = marker.get("marker_schema_version", 0)
        if ver not in rt_contract.SUPPORTED_SBPL_PREFLIGHT_MARKER_SCHEMA_VERSIONS:
            raise AssertionError(f"unsupported sbpl-preflight marker_schema_version: {ver}")
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

    failure_stage = runtime_result.get("failure_stage")
    if failure_stage == "preflight":
        if runtime_result.get("status") != "blocked":
            raise AssertionError("failure_stage=preflight but status!=blocked")
        if runtime_result.get("apply_report") is not None:
            raise AssertionError("failure_stage=preflight but apply_report is present")
        if sbpl_markers:
            raise AssertionError("failure_stage=preflight but sbpl-apply markers are present")


def _index_baseline_results(
    baseline_results: Optional[Mapping[str, Any]]
) -> tuple[Dict[tuple[str, str], Mapping[str, Any]], Dict[tuple[str, str, Optional[str]], Mapping[str, Any]]]:
    by_name: Dict[tuple[str, str], Mapping[str, Any]] = {}
    by_key: Dict[tuple[str, str, Optional[str]], Mapping[str, Any]] = {}
    if not baseline_results:
        return by_name, by_key
    rows = baseline_results.get("results") or []
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        profile_id = row.get("profile_id")
        probe_name = row.get("probe_name") or row.get("name")
        op = row.get("operation")
        target = row.get("target")
        if isinstance(profile_id, str) and isinstance(probe_name, str):
            by_name[(profile_id, probe_name)] = row
        if isinstance(profile_id, str) and isinstance(op, str):
            by_key[(profile_id, op, str(target) if target is not None else None)] = row
    return by_name, by_key


def _lookup_baseline_row(
    by_name: Mapping[tuple[str, str], Mapping[str, Any]],
    by_key: Mapping[tuple[str, str, Optional[str]], Mapping[str, Any]],
    *,
    profile_id: str,
    probe_name: Optional[str],
    operation: Optional[str],
    target: Optional[str],
) -> Optional[Mapping[str, Any]]:
    if probe_name:
        row = by_name.get((profile_id, probe_name))
        if row is not None:
            return row
    if operation:
        return by_key.get((profile_id, operation, target))
    return None


def _policy_layers_for_observation(
    *,
    baseline_row: Optional[Mapping[str, Any]],
    scenario_decision: Optional[str],
    runtime_status: Optional[str],
    failure_stage: Optional[str],
    failure_kind: Optional[str],
) -> Dict[str, Any]:
    platform_status = None
    platform_error = None
    platform_exit = None
    platform_decision = "unknown"
    platform_source = "baseline_missing"
    if baseline_row:
        platform_status = baseline_row.get("status")
        platform_error = baseline_row.get("error")
        platform_exit = baseline_row.get("exit_code")
        platform_source = "baseline"
        if platform_status in {"allow", "deny"}:
            platform_decision = platform_status

    process_decision = scenario_decision if scenario_decision in {"allow", "deny"} else "unknown"
    if failure_stage in {"apply", "bootstrap", "preflight"}:
        process_decision = "unknown"

    effective_decision = process_decision
    attribution = "unknown"
    if platform_decision == "deny":
        effective_decision = "deny"
        attribution = "platform_policy"
    elif platform_decision == "allow":
        if process_decision == "deny":
            effective_decision = "deny"
            attribution = "process_policy"
        elif process_decision == "allow":
            effective_decision = "allow"
            attribution = "allow"

    return {
        "platform_policy": {
            "decision": platform_decision,
            "status": platform_status,
            "source": platform_source,
            "error": platform_error,
            "exit_code": platform_exit,
        },
        "process_policy": {
            "decision": process_decision,
            "status": runtime_status,
            "failure_stage": failure_stage,
            "failure_kind": failure_kind,
        },
        "effective_decision": effective_decision,
        "attribution": attribution,
    }


def _tcc_sensitive(operation: Optional[str], target: Optional[str]) -> bool:
    if operation in {"device-camera", "device-microphone", "device-mic"}:
        return True
    if not target or not isinstance(target, str) or not target.startswith("/"):
        return False
    home = os.path.expanduser("~")
    if not home or not home.startswith("/"):
        return False
    for folder in ("Documents", "Downloads", "Desktop"):
        prefix = os.path.join(home, folder)
        if target == prefix or target.startswith(prefix + "/"):
            return True
    return False


def _tcc_status_from_baseline(baseline_row: Optional[Mapping[str, Any]]) -> str:
    if not baseline_row:
        return "unknown"
    if baseline_row.get("error") == "timeout":
        return "prompt_or_timeout"
    status = baseline_row.get("status")
    if status in {"allow", "deny"}:
        return status
    return "unknown"


def _tcc_status_from_scenario(
    scenario_decision: Optional[str],
    failure_stage: Optional[str],
    failure_kind: Optional[str],
) -> str:
    if failure_stage in {"apply", "bootstrap", "preflight"}:
        return "unknown"
    if failure_kind == "probe_timeout":
        return "prompt_or_timeout"
    if scenario_decision in {"allow", "deny"}:
        return scenario_decision
    return "unknown"


def _tcc_confounder_for_observation(
    *,
    operation: Optional[str],
    target: Optional[str],
    baseline_row: Optional[Mapping[str, Any]],
    scenario_decision: Optional[str],
    failure_stage: Optional[str],
    failure_kind: Optional[str],
) -> Optional[Dict[str, Any]]:
    if not _tcc_sensitive(operation, target):
        return None
    baseline_status = _tcc_status_from_baseline(baseline_row)
    scenario_status = _tcc_status_from_scenario(scenario_decision, failure_stage, failure_kind)
    attribution = "unknown"
    if baseline_status in {"deny", "prompt_or_timeout"}:
        attribution = "tcc_or_platform"
    elif baseline_status == "allow" and scenario_status in {"deny", "prompt_or_timeout"}:
        attribution = "sandbox_or_other"
    elif baseline_status == "allow" and scenario_status == "allow":
        attribution = "allow"
    return {
        "sensitive": True,
        "baseline_status": baseline_status,
        "scenario_status": scenario_status,
        "attribution": attribution,
    }


def _errno_name(value: Optional[int]) -> Optional[str]:
    if isinstance(value, int):
        return errno.errorcode.get(value)
    return None


def _file_confounder_for_observation(
    *,
    operation: Optional[str],
    errno_value: Optional[int],
    policy_layers: Optional[Mapping[str, Any]],
    failure_stage: Optional[str],
) -> Optional[Dict[str, Any]]:
    if not _is_path_operation(operation):
        return None
    if failure_stage in {"apply", "bootstrap", "preflight"}:
        return None
    if not isinstance(errno_value, int) or errno_value == 0:
        return None

    classification = "unknown"
    attribution = "unknown"
    if errno_value == errno.EACCES:
        classification = "unix_permissions"
        attribution = "unix_acl"
    elif errno_value == errno.EPERM:
        classification = "sandbox_or_mac"
        platform = None
        process = None
        if isinstance(policy_layers, Mapping):
            platform = (policy_layers.get("platform_policy") or {}).get("decision")
            process = (policy_layers.get("process_policy") or {}).get("decision")
        if process == "deny":
            attribution = "app_sandbox"
        elif platform == "deny":
            attribution = "mac"
        else:
            attribution = "sandbox_or_mac"
    else:
        classification = "other_errno"

    return {
        "errno": errno_value,
        "errno_name": _errno_name(errno_value),
        "classification": classification,
        "attribution": attribution,
    }


def _callout_op_candidates(operation: Optional[str]) -> List[str]:
    if not operation:
        return []
    if operation == "file-read*":
        return ["file-read-data", "file-read*"]
    if operation == "file-write*":
        return ["file-write-data", "file-write*"]
    return [operation]


def _sandbox_check_prepass(
    callouts: Optional[List[Dict[str, Any]]],
    operation: Optional[str],
    target: Optional[str],
) -> Optional[Dict[str, Any]]:
    if not callouts:
        return None
    def _pack(marker: Mapping[str, Any]) -> Dict[str, Any]:
        return {
            "stage": marker.get("stage"),
            "api": marker.get("api"),
            "operation": marker.get("operation"),
            "argument": marker.get("argument"),
            "filter_type": marker.get("filter_type"),
            "filter_type_name": marker.get("filter_type_name"),
            "decision": marker.get("decision"),
            "rc": marker.get("rc"),
            "errno": marker.get("errno"),
            "no_report": marker.get("no_report"),
            "no_report_reason": marker.get("no_report_reason"),
            "canonicalization": marker.get("canonicalization"),
            "canonical_flag_used": marker.get("canonical_flag_used"),
            "canonical_flag_reason": marker.get("canonical_flag_reason"),
            "token_status": marker.get("token_status"),
            "token_mach_kr": marker.get("token_mach_kr"),
        }
    candidates: List[Dict[str, Any]] = []
    op_candidates = set(_callout_op_candidates(operation))
    for marker in callouts:
        if marker.get("stage") not in {"pre_syscall", "preflight", "bootstrap_exec"}:
            continue
        if op_candidates and marker.get("operation") not in op_candidates:
            continue
        if target is not None and marker.get("argument") not in {None, target}:
            continue
        candidates.append(marker)
    if not candidates:
        return None
    if len(candidates) == 1:
        return _pack(candidates[0])
    primary = next((c for c in candidates if c.get("canonicalization") == "raw"), candidates[0])
    return {
        "primary": _pack(primary),
        "variants": [_pack(c) for c in candidates],
    }


def _resource_hygiene(runtime_result: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    record = runtime_result.get("resource_hygiene")
    if isinstance(record, Mapping):
        return dict(record)
    runner = runtime_result.get("runner_info")
    if not isinstance(runner, Mapping):
        return None
    apply_model = runner.get("apply_model")
    apply_timing = runner.get("apply_timing")
    preexisting = runner.get("preexisting_sandbox_suspected")
    if apply_model is None and apply_timing is None and preexisting is None:
        return None
    return {
        "apply_model": apply_model,
        "apply_timing": apply_timing,
        "preexisting_sandbox_suspected": preexisting,
    }

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


def observation_to_dict(obs: models.RuntimeObservation) -> Dict[str, Any]:
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


def normalize_matrix(
    expected_matrix: Mapping[str, Any],
    runtime_results: Mapping[str, Any],
    baseline_results: Optional[Mapping[str, Any]] = None,
    world_id: Optional[str] = None,
    harness_version: Optional[str] = None,
    run_id: Optional[str] = None,
) -> List[models.RuntimeObservation]:
    """
    Normalize harness output into RuntimeObservation rows.

    expected_matrix: full parsed expected_matrix.json.
    runtime_results: full parsed runtime_results.json.
    world_id: overrides the world id to stamp on observations (defaults to WORLD_ID).
    harness_version: optional string to tag the harness build/revision.
    run_id: optional run identifier to stamp on observations.
    """

    resolved_world = world_id or expected_matrix.get("world_id") or runtime_results.get("world_id") or models.WORLD_ID
    expectations_idx = _index_expectations(expected_matrix or {})
    baseline_by_name, baseline_by_key = _index_baseline_results(baseline_results)

    observations: List[models.RuntimeObservation] = []
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
            baseline_row = _lookup_baseline_row(
                baseline_by_name,
                baseline_by_key,
                profile_id=profile_id,
                probe_name=probe_name,
                operation=op,
                target=target,
            )
            stderr_canonical = _strip_sbpl_apply_markers(stderr_raw)
            rt_contract.assert_no_tool_markers_in_stderr(stderr_canonical)

            requested_path = target if _is_path_operation(op) else None
            obs = _extract_path_observation(stderr_canonical) if requested_path else {"path": None, "source": None}
            if requested_path and obs.get("path") is None:
                probe_obs = _probe_path_observation(probe)
                if probe_obs.get("path") is not None or probe_obs.get("source") is not None:
                    obs = probe_obs
            norm = _normalize_path(requested_path, obs.get("path")) if requested_path else {"path": None, "source": None}

            policy_layers = _policy_layers_for_observation(
                baseline_row=baseline_row,
                scenario_decision=actual_decision,
                runtime_status=runtime_result.get("status"),
                failure_stage=runtime_result.get("failure_stage"),
                failure_kind=runtime_result.get("failure_kind"),
            )
            errno_value = runtime_result.get("errno")
            observations.append(
                models.RuntimeObservation(
                    world_id=resolved_world,
                    profile_id=profile_id,
                    scenario_id=scenario_id,
                    run_id=run_id,
                    expectation_id=expectation_id,
                    operation=op or "",
                    target=target,
                    requested_path=requested_path,
                    observed_path=obs.get("path"),
                    observed_path_source=obs.get("source"),
                    normalized_path=norm.get("path"),
                    normalized_path_source=norm.get("source"),
                    probe_name=probe_name or expectation_rec.get("name"),
                    expected=expected_decision,
                    actual=actual_decision,
                    match=match,
                    primary_intent=probe.get("primary_intent"),
                    reached_primary_op=probe.get("reached_primary_op"),
                    intended_op_witnessed=runtime_result.get("intended_op_witnessed"),
                    first_denial_op=probe.get("first_denial_op"),
                    first_denial_filters=probe.get("first_denial_filters"),
                    decision_path=probe.get("decision_path"),
                    runtime_status=runtime_result.get("status"),
                    errno=errno_value,
                    errno_name=_errno_name(errno_value),
                    # policy_layers is required in runtime_events for attribution.
                    policy_layers=policy_layers,
                    tcc_confounder=_tcc_confounder_for_observation(
                        operation=op,
                        target=target,
                        baseline_row=baseline_row,
                        scenario_decision=actual_decision,
                        failure_stage=runtime_result.get("failure_stage"),
                        failure_kind=runtime_result.get("failure_kind"),
                    ),
                    file_confounder=_file_confounder_for_observation(
                        operation=op,
                        errno_value=errno_value,
                        policy_layers=policy_layers,
                        failure_stage=runtime_result.get("failure_stage"),
                    ),
                    sandbox_check_prepass=_sandbox_check_prepass(
                        runtime_result.get("seatbelt_callouts"),
                        op,
                        target,
                    ),
                    resource_hygiene=_resource_hygiene(runtime_result),
                    failure_stage=runtime_result.get("failure_stage"),
                    failure_kind=runtime_result.get("failure_kind"),
                    apply_report=apply_report,
                    preflight=preflight if isinstance(preflight, Mapping) else None,
                    runner_info=runtime_result.get("runner_info"),
                    seatbelt_callouts=runtime_result.get("seatbelt_callouts"),
                    entitlement_checks=runtime_result.get("entitlement_checks"),
                    probe_details=probe.get("probe_details"),
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


def write_observations(observations: Iterable[models.RuntimeObservation], out_path: Path | str) -> Path:
    """
    Write observations as a JSON array to the given path.
    """

    path = path_utils.ensure_absolute(Path(out_path), path_utils.find_repo_root(Path(__file__)))
    payload = []
    for obs in observations:
        if obs.policy_layers is None:
            raise AssertionError("runtime observation missing policy_layers attribution")
        payload.append(observation_to_dict(obs))
    path.parent.mkdir(parents=True, exist_ok=True)
    import json

    path.write_text(json.dumps(payload, indent=2, sort_keys=True))
    return path


def normalize_matrix_paths(
    expected_matrix_path: Path | str,
    runtime_results_path: Path | str,
    baseline_results_path: Optional[Path | str] = None,
    world_id: Optional[str] = None,
    harness_version: Optional[str] = None,
    run_id: Optional[str] = None,
) -> List[models.RuntimeObservation]:
    """
    Load expected_matrix + runtime_results from disk and return normalized observations.
    """

    expected_doc = load_json(expected_matrix_path)
    runtime_doc = load_json(runtime_results_path)
    baseline_doc = load_json(baseline_results_path) if baseline_results_path else None
    return normalize_matrix(
        expected_doc,
        runtime_doc,
        baseline_results=baseline_doc,
        world_id=world_id,
        harness_version=harness_version,
        run_id=run_id,
    )


def write_matrix_observations(
    expected_matrix_path: Path | str,
    runtime_results_path: Path | str,
    out_path: Path | str | None = None,
    world_id: Optional[str] = None,
    harness_version: Optional[str] = None,
    run_id: Optional[str] = None,
    baseline_results_path: Optional[Path | str] = None,
) -> Path:
    """
    Normalize events from disk and write them as a JSON array.
    """

    if out_path is None:
        raise ValueError("out_path is required")
    observations = normalize_matrix_paths(
        expected_matrix_path,
        runtime_results_path,
        baseline_results_path=baseline_results_path,
        world_id=world_id,
        harness_version=harness_version,
        run_id=run_id,
    )
    return write_observations(observations, out_path)


def normalize_metadata_results(
    runtime_results: Mapping[str, Any],
    world_id: Optional[str] = None,
    harness_version: Optional[str] = None,
    runner_info: Optional[Mapping[str, Any]] = None,
    run_id: Optional[str] = None,
    baseline_results: Optional[Mapping[str, Any]] = None,
) -> List[models.RuntimeObservation]:
    """
    Normalize metadata-runner experiment output into RuntimeObservation rows.

    metadata-runner emits a bespoke runtime_results.json shape:
    - {world_id, runner_info?, results:[{profile_id, operation, requested_path, status, errno, apply_mode, apply_rc, ...}]}
    """

    resolved_world = world_id or runtime_results.get("world_id") or models.WORLD_ID
    base_runner_info: Optional[Dict[str, Any]] = None
    if isinstance(runner_info, Mapping):
        base_runner_info = dict(runner_info)
    elif isinstance(runtime_results.get("runner_info"), Mapping):
        base_runner_info = dict(runtime_results.get("runner_info") or {})

    rows = runtime_results.get("results") or []
    if not isinstance(rows, list):
        raise AssertionError("metadata-runner runtime_results.json should contain a results list")

    baseline_by_name, baseline_by_key = _index_baseline_results(baseline_results)
    observations: List[models.RuntimeObservation] = []
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        profile_id = str(row.get("profile_id") or "")
        if not profile_id:
            continue

        preflight = row.get("preflight") if isinstance(row.get("preflight"), Mapping) else None

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

        status = row.get("status")
        failure_stage: Optional[str] = None
        failure_kind: Optional[str] = None
        apply_report = None
        runtime_status: str
        observed_errno: Optional[int] = None
        actual: Optional[str]
        violation_summary: Optional[str]

        row_failure_stage = row.get("failure_stage")
        row_failure_kind = row.get("failure_kind")
        if row_failure_stage == "preflight" or status == "blocked":
            runtime_status = "blocked"
            failure_stage = "preflight"
            failure_kind = (
                str(row_failure_kind)
                if isinstance(row_failure_kind, str) and row_failure_kind
                else "preflight_apply_gate_signature"
            )
            actual = None
            violation_summary = None
        else:
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

            runtime_status = "success" if status == "ok" else "errno"
            syscall_errno = row.get("errno") if isinstance(row.get("errno"), int) else None
            observed_errno = None if status == "ok" else syscall_errno

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

        requested_path = target if _is_path_operation(op) else None
        norm = _normalize_path(requested_path, None) if requested_path else {"path": None, "source": None}

        notes_parts: List[str] = []
        if probe_name:
            notes_parts.append(f"probe={probe_name}")
        msg = row.get("message")
        if isinstance(msg, str) and msg:
            notes_parts.append(f"message={msg}")
        notes = "; ".join(notes_parts) if notes_parts else None

        baseline_row = _lookup_baseline_row(
            baseline_by_name,
            baseline_by_key,
            profile_id=profile_id,
            probe_name=probe_name,
            operation=op,
            target=target,
        )
        policy_layers = _policy_layers_for_observation(
            baseline_row=baseline_row,
            scenario_decision=actual,
            runtime_status=runtime_status,
            failure_stage=failure_stage,
            failure_kind=failure_kind,
        )
        errno_name = str(row.get("errno_name")) if isinstance(row.get("errno_name"), str) else _errno_name(observed_errno)
        observations.append(
            models.RuntimeObservation(
                world_id=resolved_world,
                profile_id=profile_id,
                scenario_id=scenario_id,
                run_id=run_id,
                expectation_id=expectation_id,
                operation=op,
                target=target,
                requested_path=requested_path,
                observed_path=None,
                observed_path_source=None,
                normalized_path=norm.get("path"),
                normalized_path_source=norm.get("source"),
                probe_name=probe_name,
                expected=None,
                actual=actual,
                match=None,
                runtime_status=runtime_status,
                errno=observed_errno,
                errno_name=errno_name,
                policy_layers=policy_layers,
                tcc_confounder=_tcc_confounder_for_observation(
                    operation=op,
                    target=target,
                    baseline_row=baseline_row,
                    scenario_decision=actual,
                    failure_stage=failure_stage,
                    failure_kind=failure_kind,
                ),
                file_confounder=_file_confounder_for_observation(
                    operation=op,
                    errno_value=observed_errno,
                    policy_layers=policy_layers,
                    failure_stage=failure_stage,
                ),
                sandbox_check_prepass=_sandbox_check_prepass(seatbelt_markers or None, op, target),
                resource_hygiene=_resource_hygiene(runtime_result),
                failure_stage=failure_stage,
                failure_kind=failure_kind,
                apply_report=apply_report,
                preflight=dict(preflight) if preflight is not None else None,
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


def write_metadata_observations(
    runtime_results_path: Path | str,
    out_path: Path | str,
    world_id: Optional[str] = None,
    harness_version: Optional[str] = None,
    runner_info: Optional[Mapping[str, Any]] = None,
) -> Path:
    """Normalize metadata-runner results and write them as JSON observations."""
    runtime_doc = load_json(runtime_results_path)
    observations = normalize_metadata_results(runtime_doc, world_id=world_id, harness_version=harness_version, runner_info=runner_info)
    return write_observations(observations, out_path)
