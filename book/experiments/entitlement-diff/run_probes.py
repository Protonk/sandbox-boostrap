"""
Apply the compiled entitlement-diff profiles via SBPL-wrapper and run
simple network/mach probes. Results are written to out/runtime_results.json.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List

from book.api.path_utils import find_repo_root, to_repo_relative
from book.api.runtime.core import contract as rt_contract


def _load_probe_plan():
    here = Path(__file__).resolve().parent
    spec = importlib.util.spec_from_file_location("entitlement_diff.probe_plan", here / "probe_plan.py")
    if spec is None or spec.loader is None:
        raise ImportError("Failed to load probe_plan.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[attr-defined]
    return module


probe_plan = _load_probe_plan()

REPO_ROOT = find_repo_root(Path(__file__))
WRAPPER = REPO_ROOT / "book" / "tools" / "sbpl" / "wrapper" / "wrapper"
STAGE_DIR = Path("/private/tmp/entitlement-diff/app_bundle")
CONTAINER_DIR = Path("/private/tmp/entitlement-diff/container")
FILE_PROBE_TARGET = CONTAINER_DIR / "runtime.txt"

PROFILES: Dict[str, Dict[str, Path]] = {
    "baseline": {
        "blob": REPO_ROOT / "book" / "experiments" / "entitlement-diff" / "sb" / "build" / "appsandbox-baseline.sb.bin",
        "sb": REPO_ROOT / "book" / "experiments" / "entitlement-diff" / "sb" / "build" / "appsandbox-baseline.expanded.sb",
    },
    "network_mach": {
        "blob": REPO_ROOT / "book" / "experiments" / "entitlement-diff" / "sb" / "build" / "appsandbox-network-mach.sb.bin",
        "sb": REPO_ROOT / "book" / "experiments" / "entitlement-diff" / "sb" / "build" / "appsandbox-network-mach.expanded.sb",
    },
}

TESTS: List[Dict[str, object]] = probe_plan.build_probe_matrix(
    stage_dir=STAGE_DIR,
    container_dir=CONTAINER_DIR,
    repo_root=REPO_ROOT,
)

_SHA256_CACHE: Dict[str, str] = {}


def _sha256_path(path: Path) -> str:
    key = str(path)
    cached = _SHA256_CACHE.get(key)
    if cached:
        return cached
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    _SHA256_CACHE[key] = digest
    return digest


def _first_marker(markers: List[Dict[str, object]], stage: str) -> Dict[str, object] | None:
    for marker in markers:
        if marker.get("stage") == stage:
            return marker
    return None


def run_probe(profile: Path, command: List[str]) -> Dict[str, object]:
    full_cmd = [str(WRAPPER), "--blob", str(profile), "--"] + command
    try:
        res = subprocess.run(full_cmd, capture_output=True, text=True, timeout=15)
        stderr_raw = res.stderr or ""
        apply_markers = rt_contract.extract_sbpl_apply_markers(stderr_raw)
        apply_marker = _first_marker(apply_markers, "apply")
        applied_marker = _first_marker(apply_markers, "applied")
        exec_marker = _first_marker(apply_markers, "exec")
        seatbelt_callouts = rt_contract.extract_seatbelt_callout_markers(stderr_raw) or None

        apply_report = rt_contract.derive_apply_report_from_markers(apply_markers)
        failure_stage = None
        failure_kind = None
        observed_errno = None

        apply_rc = apply_marker.get("rc") if apply_marker else None
        if isinstance(apply_rc, int) and apply_rc != 0:
            failure_stage = "apply"
            api = apply_marker.get("api") if apply_marker else None
            err_class = apply_marker.get("err_class") if apply_marker else None
            if err_class == "already_sandboxed":
                failure_kind = "apply_already_sandboxed"
            else:
                failure_kind = f"{api}_failed" if isinstance(api, str) and api else "apply_failed"
            observed_errno = apply_marker.get("errno") if apply_marker else None
        else:
            exec_rc = exec_marker.get("rc") if exec_marker else None
            if isinstance(exec_rc, int) and exec_rc != 0:
                failure_stage = "bootstrap"
                observed_errno = exec_marker.get("errno") if exec_marker else None
                if applied_marker is not None and observed_errno == 1:
                    failure_kind = "bootstrap_deny_process_exec"
                else:
                    failure_kind = "bootstrap_exec_failed"
            elif res.returncode != 0:
                failure_stage = "probe"
                failure_kind = "probe_nonzero_exit"
                observed_errno = res.returncode

        status = "ok" if res.returncode == 0 else "deny"
        if failure_stage in {"apply", "bootstrap"}:
            status = "blocked"

        stderr_canonical = rt_contract.strip_tool_markers(stderr_raw)
        runner_info = {
            "entrypoint": "SBPL-wrapper",
            "apply_model": "exec_wrapper",
            "apply_timing": "pre_exec",
            "entrypoint_path": to_repo_relative(WRAPPER, REPO_ROOT),
            "entrypoint_sha256": _sha256_path(WRAPPER),
            "tool_build_id": _sha256_path(WRAPPER),
        }

        runtime_result = {
            "status": "success" if res.returncode == 0 else "errno",
            "errno": None if res.returncode == 0 else observed_errno,
            "runtime_result_schema_version": rt_contract.CURRENT_RUNTIME_RESULT_SCHEMA_VERSION,
            "tool_marker_schema_version": rt_contract.CURRENT_TOOL_MARKER_SCHEMA_VERSION,
            "failure_stage": failure_stage,
            "failure_kind": failure_kind,
            "apply_report": apply_report,
            "runner_info": runner_info,
            "seatbelt_callouts": seatbelt_callouts,
        }

        return {
            "command": full_cmd,
            "exit_code": res.returncode,
            "stdout": res.stdout,
            "stderr": stderr_canonical,
            "status": status,
            "runtime_result": runtime_result,
        }
    except Exception as exc:  # pragma: no cover - runtime helper
        return {"command": full_cmd, "error": str(exc), "status": "error"}


def main() -> int:
    STAGE_DIR.mkdir(parents=True, exist_ok=True)
    for spec in probe_plan.staged_binary_specs(REPO_ROOT):
        shutil.copy2(spec.src_path, STAGE_DIR / spec.dest_name)
    CONTAINER_DIR.mkdir(parents=True, exist_ok=True)
    FILE_PROBE_TARGET.write_text("entitlement-diff runtime file\n")

    preflight_enabled = os.environ.get("SANDBOX_LORE_PREFLIGHT") != "0"
    preflight_force = os.environ.get("SANDBOX_LORE_PREFLIGHT_FORCE") == "1"

    results: Dict[str, Dict[str, object]] = {}
    for profile_name, paths in PROFILES.items():
        blob = paths["blob"]
        sb_path = paths["sb"]
        preflight_record = None
        preflight_blocked = False
        if preflight_enabled:
            try:
                from book.tools.preflight import preflight as preflight_mod  # type: ignore

                rec_obj = preflight_mod.preflight_path(sb_path)
                preflight_record = rec_obj.to_json()
                if (
                    preflight_record.get("classification") == "likely_apply_gated_for_harness_identity"
                    and not preflight_force
                ):
                    preflight_blocked = True
            except Exception:
                preflight_record = None
                preflight_blocked = False
        profile_results: Dict[str, object] = {
            "profile_blob": to_repo_relative(blob, REPO_ROOT),
            "profile_sbpl": to_repo_relative(sb_path, REPO_ROOT),
        }
        if preflight_record is not None:
            profile_results["preflight"] = preflight_record
        for test in TESTS:
            if preflight_blocked:
                digest = _sha256_path(WRAPPER)
                runner_info = {
                    "entrypoint": "SBPL-wrapper",
                    "apply_model": "exec_wrapper",
                    "apply_timing": "pre_exec",
                    "entrypoint_path": to_repo_relative(WRAPPER, REPO_ROOT),
                    "entrypoint_sha256": digest,
                    "tool_build_id": digest,
                }
                runtime_result = {
                    "status": "blocked",
                    "errno": None,
                    "runtime_result_schema_version": rt_contract.CURRENT_RUNTIME_RESULT_SCHEMA_VERSION,
                    "tool_marker_schema_version": rt_contract.CURRENT_TOOL_MARKER_SCHEMA_VERSION,
                    "failure_stage": "preflight",
                    "failure_kind": "preflight_apply_gate_signature",
                    "apply_report": None,
                    "runner_info": runner_info,
                    "seatbelt_callouts": None,
                }
                probe_res: Dict[str, object] = {
                    "command": [],
                    "exit_code": None,
                    "stdout": "",
                    "stderr": "",
                    "status": "blocked",
                    "runtime_result": runtime_result,
                    "preflight": preflight_record,
                    "notes": "preflight blocked: known apply-gate signature",
                }
            else:
                probe_res = run_probe(blob, test["command"])  # type: ignore[arg-type]
            profile_results[test["id"]] = {"wrapper": probe_res}
        results[profile_name] = profile_results

    out_path = REPO_ROOT / "book" / "experiments" / "entitlement-diff" / "out" / "runtime_results.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(results, indent=2) + "\n")
    print(f"[+] wrote {to_repo_relative(out_path, REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
