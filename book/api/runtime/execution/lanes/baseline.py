"""
Baseline (unsandboxed) probe execution for runtime tools.

Baseline results are used to disambiguate platform restrictions from
profile-attributed decisions.

The baseline lane answers "what happens without a profile?" so we
can avoid blaming the sandbox for ambient platform behavior.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional

from book.api import path_utils
from book.api.runtime.execution.harness import runner as harness_runner


REPO_ROOT = path_utils.find_repo_root(Path(__file__))


def _extract_probe_details(stdout: str) -> tuple[Optional[Dict[str, Any]], str]:
    if not stdout:
        return None, ""
    details: Optional[Dict[str, Any]] = None
    cleaned_lines = []
    for line in stdout.splitlines():
        if line.startswith("SBL_PROBE_DETAILS "):
            payload = line[len("SBL_PROBE_DETAILS ") :].strip()
            if payload:
                try:
                    details = json.loads(payload)
                except Exception:
                    details = {"error": "invalid_probe_details_json"}
            continue
        cleaned_lines.append(line)
    cleaned = "\n".join(cleaned_lines)
    if stdout.endswith("\n") and cleaned:
        cleaned += "\n"
    return details, cleaned


def _baseline_path_observation(target: Optional[str]) -> Dict[str, Any]:
    if not target:
        return {"observed_path": None, "observed_path_source": "unsandboxed_missing_target"}
    return harness_runner._unsandboxed_path_observation(target)


def _command_for_probe(op: str, target: Optional[str]) -> list[str]:
    probe = {"operation": op, "target": target}
    return harness_runner.build_probe_command(probe)


def run_baseline_for_probe(profile_id: str, probe: Dict[str, Any]) -> Dict[str, Any]:
    """Run a single probe without applying any profile."""
    op = probe.get("operation") or ""
    target = probe.get("target")
    cmd = _command_for_probe(op, target)
    record: Dict[str, Any] = {
        "name": f"baseline:{profile_id}:{probe.get('name')}",
        "profile_id": profile_id,
        "probe_name": probe.get("name"),
        "operation": op,
        "target": target,
        "primary_intent": {
            "operation": op,
            "target": target,
            "profile_id": profile_id,
            "probe_name": probe.get("name"),
        },
        "command": path_utils.relativize_command(cmd, repo_root=REPO_ROOT),
    }
    if op.startswith("file-"):
        record.update(_baseline_path_observation(target))
    try:
        listener_info = None
        if op == "network-outbound":
            with harness_runner._loopback_listener(target) as listener_info:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        else:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        probe_details, stdout_clean = _extract_probe_details(res.stdout or "")
        record["status"] = "allow" if res.returncode == 0 else "deny"
        record["exit_code"] = res.returncode
        # Truncate outputs to keep baseline artifacts compact.
        record["stdout"] = stdout_clean[:200]
        record["stderr"] = (res.stderr or "")[:200]
        record["reached_primary_op"] = True
        record["decision_path"] = "baseline"
        if probe_details is not None:
            record["probe_details"] = probe_details
        if listener_info is not None:
            record["listener"] = listener_info
    except subprocess.TimeoutExpired:
        record["status"] = "deny"
        record["error"] = "timeout"
    except Exception as exc:
        record["status"] = "deny"
        record["error"] = str(exc)
    return record


def build_baseline_results(world_id: str, profiles: list[Dict[str, Any]], run_id: Optional[str]) -> Dict[str, Any]:
    """Build a baseline_results document for a list of profiles."""
    results = []
    for profile in profiles:
        profile_id = profile.get("profile_id")
        for probe in profile.get("probes") or []:
            results.append(run_baseline_for_probe(profile_id, probe))
    return {
        "schema_version": "runtime-tools.baseline_results.v0.1",
        "world_id": world_id,
        "run_id": run_id,
        "results": results,
    }
