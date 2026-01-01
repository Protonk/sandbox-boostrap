"""Baseline comparison helpers for PolicyWitness actions."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Optional, Sequence

from book.api import exec_record, path_utils, tooling
from book.api.profile.identity import baseline_world_id
from book.api.runtime.contracts import schema as runtime_schema
from book.api.runtime.execution import preflight as runtime_preflight
from book.api.witness import outputs
from book.api.witness.client import run_probe_request
from book.api.witness.models import (
    ActionSpec,
    CommandResult,
    CommandSpec,
    ComparisonReport,
    EntitlementAction,
    ProbeRequest,
    SbplAction,
)
from book.api.witness.paths import REPO_ROOT


def _run_command(argv: Sequence[str], *, cwd: Optional[Path], timeout_s: Optional[float]) -> CommandResult:
    record = exec_record.run_command(argv, cwd=cwd, timeout_s=timeout_s, repo_root=REPO_ROOT)
    return CommandResult(
        command=record.get("command") or [],
        exit_code=record.get("exit_code"),
        stdout=record.get("stdout") or "",
        stderr=record.get("stderr") or "",
        started_at_unix_s=record.get("cmd_started_at_unix_s") or 0.0,
        finished_at_unix_s=record.get("cmd_finished_at_unix_s") or 0.0,
        duration_s=record.get("cmd_duration_s") or 0.0,
        error=record.get("error"),
    )


def _run_command_spec(spec: CommandSpec) -> CommandResult:
    cwd = path_utils.ensure_absolute(spec.cwd, REPO_ROOT) if spec.cwd else None
    return _run_command(spec.argv, cwd=cwd, timeout_s=spec.timeout_s)


def _sbpl_wrapper_path() -> Path:
    return path_utils.ensure_absolute(Path("book/tools/sbpl/wrapper/wrapper"), REPO_ROOT)


def _sandbox_runner_path() -> Path:
    return path_utils.ensure_absolute(Path("book/api/runtime/native/sandbox_runner/sandbox_runner"), REPO_ROOT)


def _sbpl_wrapper_cmd(action: SbplAction) -> list[str]:
    wrapper = _sbpl_wrapper_path()
    if not wrapper.exists():
        raise FileNotFoundError(f"sbpl wrapper missing: {path_utils.to_repo_relative(wrapper, REPO_ROOT)}")
    cmd = [str(wrapper)]
    if action.preflight:
        cmd += ["--preflight", action.preflight]
    if action.sbpl_path:
        sbpl_path = path_utils.ensure_absolute(action.sbpl_path, REPO_ROOT)
        cmd += ["--sbpl", str(sbpl_path)]
    elif action.blob_path:
        blob_path = path_utils.ensure_absolute(action.blob_path, REPO_ROOT)
        cmd += ["--blob", str(blob_path)]
    else:
        raise ValueError("sbpl action requires sbpl_path or blob_path")
    return cmd


def _sbpl_preflight_record(action: SbplAction) -> Dict[str, object]:
    preflight_mode = str(action.preflight or "").strip().lower()
    if preflight_mode in {"off", "disabled"}:
        return {"status": "skipped", "reason": "disabled_by_action"}
    if not action.sbpl_path:
        return {"status": "skipped", "reason": "missing_text_profile"}
    profile_path = path_utils.ensure_absolute(action.sbpl_path, REPO_ROOT)
    runner_path = _sandbox_runner_path()
    return runtime_preflight.run_apply_preflight(
        world_id=baseline_world_id(REPO_ROOT),
        profile_path=profile_path,
        runner_path=runner_path,
    )


def _run_sbpl_action(action: SbplAction) -> CommandResult:
    cmd_spec = action.command
    cwd = path_utils.ensure_absolute(cmd_spec.cwd, REPO_ROOT) if cmd_spec.cwd else None
    wrapper_cmd = _sbpl_wrapper_cmd(action)
    cmd = [*wrapper_cmd, "--", *cmd_spec.argv]
    result = _run_command(cmd, cwd=cwd, timeout_s=cmd_spec.timeout_s)
    result.runner_info = tooling.runner_info(
        _sbpl_wrapper_path(),
        repo_root=REPO_ROOT,
        entrypoint="sbpl-wrapper",
    )
    result.preflight = _sbpl_preflight_record(action)
    markers = {
        "sbpl_apply": runtime_schema.extract_sbpl_apply_markers(result.stderr),
        "sbpl_preflight": runtime_schema.extract_sbpl_preflight_markers(result.stderr),
        "sbpl_compile": runtime_schema.extract_sbpl_compile_markers(result.stderr),
    }
    if any(markers.values()):
        result.tool_markers = {k: v for k, v in markers.items() if v}
    return result


def _write_result(payload: Dict[str, object], output_spec: Optional[outputs.OutputSpec]) -> Optional[str]:
    if output_spec is None:
        return None
    out_paths = outputs.resolve_output_paths(output_spec, plan_id=None, row_id=None, probe_id=None)
    target = out_paths.record_path or out_paths.log_path
    if target is None:
        return None
    return outputs.write_json(target, payload, indent=output_spec.json_indent, sort_keys=output_spec.json_sort_keys)


def _entitlement_request(action: EntitlementAction, *, action_id: str) -> ProbeRequest:
    plan_id = action.plan_id or f"witness:compare:{action_id}"
    return ProbeRequest(
        profile_id=action.profile_id,
        service_id=action.service_id,
        probe_id=action.probe_id,
        probe_args=action.probe_args,
        plan_id=plan_id,
        row_id=action.row_id or action_id,
        correlation_id=action.correlation_id,
        capture_sandbox_logs=action.capture_sandbox_logs,
        timeout_s=action.timeout_s,
    )


def compare_action(
    action: ActionSpec,
    *,
    output: Optional[outputs.OutputSpec] = None,
    observer: bool = True,
) -> ComparisonReport:
    results: Dict[str, Dict[str, object]] = {}
    limits: list[str] = []
    world_id = baseline_world_id(REPO_ROOT)

    if action.entitlements:
        ent_output = outputs.fork_output(output, prefix=f"{action.action_id}.entitlements")
        probe_request = _entitlement_request(action.entitlements, action_id=action.action_id)
        probe_result = run_probe_request(probe_request, output=ent_output, observer=observer)
        results["entitlements"] = probe_result.to_json()
        limits.append("entitlements: PolicyWitness XPC run (observer-only deny evidence)")

    if action.sbpl:
        sbpl_output = outputs.fork_output(output, prefix=f"{action.action_id}.sbpl")
        sbpl_result = _run_sbpl_action(action.sbpl)
        payload = sbpl_result.to_json()
        write_error = _write_result(payload, sbpl_output)
        if write_error:
            payload["write_error"] = write_error
        results["sbpl"] = payload
        limits.append("sbpl: wrapper apply failures are apply-stage gates, not policy decisions")

    if action.none:
        none_output = outputs.fork_output(output, prefix=f"{action.action_id}.none")
        none_result = _run_command_spec(action.none)
        payload = none_result.to_json()
        write_error = _write_result(payload, none_output)
        if write_error:
            payload["write_error"] = write_error
        results["none"] = payload
        limits.append("none: unsandboxed baseline (no policy apply)")

    return ComparisonReport(action_id=action.action_id, world_id=world_id, results=results, limits=limits)
