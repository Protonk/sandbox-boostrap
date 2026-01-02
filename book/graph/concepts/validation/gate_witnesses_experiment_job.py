"""
Validation job for the gate-witnesses experiment.

This job re-runs the checked-in minimized witness pairs and asserts that they
still witness the intended boundary on this world:

- minimal failing: apply-stage EPERM (profile did not attach)
- passing neighbor: failure_stage != "apply" (not apply-gated)

If sandbox_init is globally gated in the current execution environment (e.g.,
inside a harness sandbox), this job reports status=blocked.
"""

from __future__ import annotations

import json
import os
import subprocess
import hashlib
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from book.api.path_utils import find_repo_root, to_repo_relative
from book.api.runtime.contracts import schema as rt_contract
from book.api.runtime.contracts import models as runtime_models
from book.graph.concepts.validation import registry
from book.graph.concepts.validation.registry import ValidationJob

ROOT = find_repo_root(Path(__file__))
WITNESS_ROOT = ROOT / "book/experiments/runtime-final-final/suites/gate-witnesses/out/witnesses"
OUT_DIR = ROOT / "book/graph/concepts/validation/out/experiments/gate-witnesses"
STATUS_PATH = OUT_DIR / "status.json"
RESULTS_PATH = OUT_DIR / "witness_results.json"

WRAPPER = ROOT / "book/tools/sbpl/wrapper/wrapper"
CONTROL_SBPL = ROOT / "book/experiments/op-table-operation/sb/v0_empty.sb"

EPERM = 1

CLEAR_LOG_ENV = "SANDBOX_LORE_CAPTURE_UNIFIED_LOG"


def rel(path: Path) -> str:
    return to_repo_relative(path, ROOT)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _run_wrapper(sbpl_path: Path, timeout_sec: int = 5) -> Dict[str, Any]:
    cmd_exec = [str(WRAPPER), "--preflight", "force", "--sbpl", str(sbpl_path), "--", "/usr/bin/true"]
    cmd = [rel(WRAPPER), "--preflight", "force", "--sbpl", rel(sbpl_path), "--", "/usr/bin/true"]
    start_unix = time.time()
    proc = subprocess.Popen(cmd_exec, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        _, stderr_raw = proc.communicate(timeout=timeout_sec)
        timed_out = False
    except subprocess.TimeoutExpired:
        proc.kill()
        _, stderr_raw = proc.communicate()
        timed_out = True
    end_unix = time.time()
    stderr_raw = stderr_raw or ""
    upgraded = rt_contract.upgrade_runtime_result({}, stderr_raw)
    return {
        "cmd": cmd,
        "wrapper_rc": proc.returncode,
        "pid": proc.pid,
        "timed_out": timed_out,
        "start_unix": start_unix,
        "end_unix": end_unix,
        "failure_stage": upgraded.get("failure_stage") if isinstance(upgraded.get("failure_stage"), str) else None,
        "failure_kind": upgraded.get("failure_kind") if isinstance(upgraded.get("failure_kind"), str) else None,
        "apply_report": upgraded.get("apply_report") if isinstance(upgraded.get("apply_report"), dict) else None,
        "entitlement_checks": upgraded.get("entitlement_checks") if isinstance(upgraded.get("entitlement_checks"), list) else None,
        "stderr": rt_contract.strip_tool_markers(stderr_raw) or "",
    }


def _run_wrapper_compile(sbpl_path: Path, out_blob: Path, timeout_sec: int = 10) -> Dict[str, Any]:
    out_blob.parent.mkdir(parents=True, exist_ok=True)
    cmd_exec = [str(WRAPPER), "--compile", str(sbpl_path), "--out", str(out_blob)]
    cmd = [rel(WRAPPER), "--compile", rel(sbpl_path), "--out", rel(out_blob)]
    start_unix = time.time()
    proc = subprocess.Popen(cmd_exec, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        _, stderr_raw = proc.communicate(timeout=timeout_sec)
        timed_out = False
    except subprocess.TimeoutExpired:
        proc.kill()
        _, stderr_raw = proc.communicate()
        timed_out = True
    end_unix = time.time()
    stderr_raw = stderr_raw or ""
    markers = rt_contract.extract_sbpl_compile_markers(stderr_raw)
    marker = markers[0] if markers else None
    marker_fields = {
        "marker_schema_version": marker.get("marker_schema_version") if isinstance(marker, dict) else None,
        "rc": marker.get("rc") if isinstance(marker, dict) else None,
        "errno": marker.get("errno") if isinstance(marker, dict) else None,
        "errbuf": marker.get("errbuf") if isinstance(marker, dict) else None,
        "profile_type": marker.get("profile_type") if isinstance(marker, dict) else None,
        "bytecode_length": marker.get("bytecode_length") if isinstance(marker, dict) else None,
    }
    blob_sha256 = sha256_file(out_blob) if out_blob.exists() else None
    return {
        "cmd": cmd,
        "wrapper_rc": proc.returncode,
        "pid": proc.pid,
        "timed_out": timed_out,
        "start_unix": start_unix,
        "end_unix": end_unix,
        "blob": rel(out_blob),
        "blob_sha256": blob_sha256,
        "marker": marker_fields,
        "marker_count": len(markers),
        "stderr": rt_contract.strip_tool_markers(stderr_raw) or "",
    }


def _run_wrapper_blob(blob_path: Path, timeout_sec: int = 5) -> Dict[str, Any]:
    cmd_exec = [str(WRAPPER), "--preflight", "force", "--blob", str(blob_path), "--", "/usr/bin/true"]
    cmd = [rel(WRAPPER), "--preflight", "force", "--blob", rel(blob_path), "--", "/usr/bin/true"]
    start_unix = time.time()
    proc = subprocess.Popen(cmd_exec, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        _, stderr_raw = proc.communicate(timeout=timeout_sec)
        timed_out = False
    except subprocess.TimeoutExpired:
        proc.kill()
        _, stderr_raw = proc.communicate()
        timed_out = True
    end_unix = time.time()
    stderr_raw = stderr_raw or ""
    upgraded = rt_contract.upgrade_runtime_result({}, stderr_raw)
    blob_sha256 = sha256_file(blob_path) if blob_path.exists() else None
    return {
        "cmd": cmd,
        "wrapper_rc": proc.returncode,
        "pid": proc.pid,
        "timed_out": timed_out,
        "start_unix": start_unix,
        "end_unix": end_unix,
        "blob": rel(blob_path),
        "blob_sha256": blob_sha256,
        "failure_stage": upgraded.get("failure_stage") if isinstance(upgraded.get("failure_stage"), str) else None,
        "failure_kind": upgraded.get("failure_kind") if isinstance(upgraded.get("failure_kind"), str) else None,
        "apply_report": upgraded.get("apply_report") if isinstance(upgraded.get("apply_report"), dict) else None,
        "entitlement_checks": upgraded.get("entitlement_checks") if isinstance(upgraded.get("entitlement_checks"), list) else None,
        "stderr": rt_contract.strip_tool_markers(stderr_raw) or "",
    }


def _log_show_window_for_run(start_unix: float, end_unix: float, pad_seconds: int = 2) -> Dict[str, Any]:
    start_i = max(0, int(start_unix) - pad_seconds)
    end_i = max(start_i, int(end_unix) + pad_seconds)
    return {
        "run_start_unix": start_unix,
        "run_end_unix": end_unix,
        "log_start_unix": start_i,
        "log_end_unix": end_i,
        "log_start": f"@{start_i}",
        "log_end": f"@{end_i}",
    }


def _capture_unified_log(out_path: Path, start_unix: float, end_unix: float, predicate: str) -> Dict[str, Any]:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    window = _log_show_window_for_run(start_unix, end_unix)
    cmd = [
        "/usr/bin/log",
        "show",
        "--style",
        "syslog",
        "--start",
        window["log_start"],
        "--end",
        window["log_end"],
        "--predicate",
        predicate,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    stdout = proc.stdout or ""
    prefix = str(ROOT) + "/"
    if prefix in stdout:
        stdout = stdout.replace(prefix, "")
    (out_path).write_text(stdout)
    return {
        "cmd": cmd,
        "rc": proc.returncode,
        "out_path": rel(out_path),
        "start": window["log_start"],
        "end": window["log_end"],
        "start_unix": window["log_start_unix"],
        "end_unix": window["log_end_unix"],
        "run_start_unix": window["run_start_unix"],
        "run_end_unix": window["run_end_unix"],
        "predicate": predicate,
        "stderr": (proc.stderr or "").strip() or None,
        "stdout_bytes": len(proc.stdout.encode("utf-8")) if proc.stdout else 0,
    }


def _is_apply_gate_eperm(result: Dict[str, Any]) -> bool:
    if result.get("failure_stage") != "apply":
        return False
    report = result.get("apply_report")
    if not isinstance(report, dict):
        return False
    return report.get("errno") == EPERM


def _is_not_apply_gate(result: Dict[str, Any]) -> bool:
    return result.get("failure_stage") != "apply"


def run_gate_witnesses_job() -> Dict[str, Any]:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    capture_unified_log = bool(os.environ.get(CLEAR_LOG_ENV))

    if not WITNESS_ROOT.exists():
        raise FileNotFoundError(f"missing witness root: {WITNESS_ROOT}")
    if not WRAPPER.exists():
        raise FileNotFoundError(f"missing wrapper binary: {WRAPPER}")

    # Environment sanity: if sandbox_init is globally gated here, witnesses are not meaningful.
    control = _run_wrapper(CONTROL_SBPL)
    if _is_apply_gate_eperm(control):
        payload = {
            "job_id": "experiment:gate-witnesses",
            "status": "blocked",
            "tier": "mapped",
            "host": {},
            "inputs": [rel(CONTROL_SBPL)],
            "outputs": [rel(RESULTS_PATH), rel(STATUS_PATH)],
            "notes": "sandbox_init appears globally apply-gated in this execution context (control profile failed apply-stage EPERM); rerun outside the harness sandbox.",
            "metrics": {"witnesses": 0},
        }
        RESULTS_PATH.write_text(
            json.dumps(
                {
                    "world_id": runtime_models.WORLD_ID,
                    "control": control,
                    "witnesses": [],
                },
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
        STATUS_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        return {
            "status": "blocked",
            "tier": "mapped",
            "inputs": payload["inputs"],
            "outputs": payload["outputs"],
            "metrics": payload["metrics"],
            "notes": payload["notes"],
        }

    results: List[Dict[str, Any]] = []
    failures: List[str] = []

    for dirpath in sorted(p for p in WITNESS_ROOT.iterdir() if p.is_dir()):
        failing_path = dirpath / "minimal_failing.sb"
        neighbor_path = dirpath / "passing_neighbor.sb"
        if not failing_path.exists() or not neighbor_path.exists():
            continue

        failing = _run_wrapper(failing_path)
        neighbor = _run_wrapper(neighbor_path)

        forensics: Optional[Dict[str, Any]] = None
        if capture_unified_log:
            # Prefer sandbox reporting / sandbox image logs, but keep a fallback predicate that is message-filter focused.
            primary_predicate = (
                '((subsystem == "com.apple.sandbox.reporting") OR (senderImagePath CONTAINS[c] "/Sandbox")) AND '
                '((eventMessage CONTAINS[c] "message filter") OR (eventMessage CONTAINS[c] "message-filter") OR '
                '(eventMessage CONTAINS[c] "entitlement"))'
            )
            fallback_predicate = (
                '(eventMessage CONTAINS[c] "message filter") OR (eventMessage CONTAINS[c] "message-filter") OR '
                '(eventMessage CONTAINS[c] "entitlement")'
            )
            forensics_dir = OUT_DIR / "forensics" / dirpath.name
            forensics_dir.mkdir(parents=True, exist_ok=True)

            failing_blob_path = forensics_dir / "minimal_failing.sb.bin"
            neighbor_blob_path = forensics_dir / "passing_neighbor.sb.bin"

            compile_minimal_failing = _run_wrapper_compile(failing_path, failing_blob_path)
            compile_passing_neighbor = _run_wrapper_compile(neighbor_path, neighbor_blob_path)

            blob_apply_minimal_failing: Optional[Dict[str, Any]] = None
            if failing_blob_path.exists():
                blob_apply_minimal_failing = _run_wrapper_blob(failing_blob_path)

            blob_apply_passing_neighbor: Optional[Dict[str, Any]] = None
            if neighbor_blob_path.exists():
                blob_apply_passing_neighbor = _run_wrapper_blob(neighbor_blob_path)

            def capture_logs(label: str, apply_result: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
                if not isinstance(apply_result, dict):
                    return None
                pid = apply_result.get("pid")
                start_unix = apply_result.get("start_unix")
                end_unix = apply_result.get("end_unix")
                if not isinstance(pid, int) or not isinstance(start_unix, (float, int)) or not isinstance(end_unix, (float, int)):
                    return None
                pid_term = f'(eventMessage CONTAINS[c] "wrapper[{pid}]")'
                primary = f"({primary_predicate}) AND {pid_term}"
                fallback = f"({fallback_predicate}) AND {pid_term}"
                log_primary_path = forensics_dir / f"log_show_primary.{label}.txt"
                log_primary = _capture_unified_log(log_primary_path, float(start_unix), float(end_unix), primary)
                log_fallback_path = forensics_dir / f"log_show_fallback.{label}.txt"
                log_fallback = _capture_unified_log(log_fallback_path, float(start_unix), float(end_unix), fallback)

                # Back-compat / human convenience: keep the unsuffixed filenames as aliases for minimal_failing.
                if label == "minimal_failing":
                    (forensics_dir / "log_show_primary.txt").write_text(log_primary_path.read_text(encoding="utf-8"), encoding="utf-8")
                    (forensics_dir / "log_show_fallback.txt").write_text(log_fallback_path.read_text(encoding="utf-8"), encoding="utf-8")

                return {
                    "pid": pid,
                    "primary": log_primary,
                    "fallback": log_fallback,
                }

            unified_log = {
                "minimal_failing": capture_logs("minimal_failing", blob_apply_minimal_failing),
                "passing_neighbor": capture_logs("passing_neighbor", blob_apply_passing_neighbor),
            }
            forensics = {
                "capture_unified_log": True,
                "compile": {
                    "minimal_failing": compile_minimal_failing,
                    "passing_neighbor": compile_passing_neighbor,
                },
                "blob_apply": {
                    "minimal_failing": blob_apply_minimal_failing,
                    "passing_neighbor": blob_apply_passing_neighbor,
                },
                "unified_log": unified_log,
            }

        ok = _is_apply_gate_eperm(failing) and _is_not_apply_gate(neighbor)
        if not ok:
            failures.append(dirpath.name)

        results.append(
            {
                "target": dirpath.name,
                "minimal_failing": {"path": rel(failing_path), "result": failing},
                "passing_neighbor": {"path": rel(neighbor_path), "result": neighbor},
                "forensics": forensics,
                "ok": ok,
            }
        )

    RESULTS_PATH.write_text(
        json.dumps(
            {
                "world_id": runtime_models.WORLD_ID,
                "control": control,
                "witnesses": results,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )

    status = "ok" if not failures else "partial"
    notes: Optional[str] = None
    if failures:
        notes = f"witness predicate failed for: {', '.join(failures)}"

    payload = {
        "job_id": "experiment:gate-witnesses",
        "status": status,
        "tier": "mapped",
        "host": {},
        "inputs": [rel(WITNESS_ROOT)],
        "outputs": [rel(RESULTS_PATH), rel(STATUS_PATH)],
        "metrics": {"witnesses": len(results), "failures": len(failures)},
        "notes": notes or "Verified apply-gate witness pairs via SBPL-wrapper and runtime contract classification.",
        "tags": ["experiment:gate-witnesses", "experiment", "apply-gate"],
    }
    STATUS_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")

    return {
        "status": status,
        "tier": "mapped",
        "inputs": payload["inputs"],
        "outputs": payload["outputs"],
        "metrics": payload["metrics"],
        "notes": payload["notes"],
        "host": payload["host"],
    }


registry.register(
    ValidationJob(
        id="experiment:gate-witnesses",
        inputs=[rel(WITNESS_ROOT)],
        outputs=[rel(RESULTS_PATH), rel(STATUS_PATH)],
        tags=["experiment:gate-witnesses", "experiment", "apply-gate"],
        description="Re-run minimized apply-gate witnesses and assert they still witness apply-stage EPERM boundaries on this world.",
        example_command="python -m book.graph.concepts.validation --experiment gate-witnesses",
        runner=run_gate_witnesses_job,
    )
)
