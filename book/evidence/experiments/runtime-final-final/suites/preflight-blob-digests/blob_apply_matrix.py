#!/usr/bin/env python3
"""
Apply compiled blobs (`.sb.bin`) via SBPL-wrapper and record apply-stage outcomes.

This script is phase-aware: it treats apply-stage EPERM as blocked-entrypoint
evidence (apply gate), not as a PolicyGraph decision.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api.path_utils import to_repo_relative  # type: ignore
from book.api.runtime.contracts import schema as rt_contract  # type: ignore
from book.api.profile import identity as identity_mod  # type: ignore


SCHEMA_VERSION = 1
WRAPPER = REPO_ROOT / "book" / "tools" / "sbpl" / "wrapper" / "wrapper"


def _rel(path: Path) -> str:
    return to_repo_relative(path, REPO_ROOT)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _run_wrapper_blob(blob_path: Path, timeout_sec: int = 5) -> Dict[str, Any]:
    blob_abs = blob_path.resolve()
    cmd_exec = [str(WRAPPER), "--preflight", "force", "--blob", str(blob_abs), "--", "/usr/bin/true"]
    cmd = [ _rel(WRAPPER), "--preflight", "force", "--blob", _rel(blob_abs), "--", "/usr/bin/true"]
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


def _classify_apply_gate(result: Dict[str, Any]) -> str:
    stage = result.get("failure_stage")
    report = result.get("apply_report") if isinstance(result.get("apply_report"), dict) else None
    if stage == "apply" and isinstance(report, dict) and report.get("errno") == 1:
        return "apply_gated_eperm"
    if stage == "apply":
        return "apply_failed_other"
    if stage in {"bootstrap", "probe"}:
        return "not_apply_gated"
    # If stage is None but apply_report is ok, treat as not apply gated.
    if isinstance(report, dict) and report.get("rc") == 0:
        return "not_apply_gated"
    return "unknown"


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="blob_apply_matrix")
    ap.add_argument("--blob", action="append", default=[], help=".sb.bin path (repeatable)")
    ap.add_argument(
        "--control-blob",
        type=Path,
        default=REPO_ROOT / "book/evidence/experiments/op-table-operation/sb/build/v0_empty.sb.bin",
        help="known non-apply-gated control blob (default: v0_empty.sb.bin)",
    )
    ap.add_argument("--label", default=None, help="optional run label (e.g. in_harness, outside_harness)")
    ap.add_argument("--out", type=Path, required=True, help="output JSON path")
    args = ap.parse_args(argv)

    if not WRAPPER.exists():
        raise FileNotFoundError(f"missing wrapper: {WRAPPER}")

    world_id = identity_mod.baseline_world_id()

    control_blob = args.control_blob
    control_sha = _sha256_file(control_blob) if control_blob.exists() else None
    control_run = _run_wrapper_blob(control_blob) if control_blob.exists() else {"error": "missing control blob"}
    control = {
        "blob": _rel(control_blob),
        "blob_sha256": control_sha,
        "result": control_run,
        "classification": _classify_apply_gate(control_run) if "error" not in control_run else "invalid",
    }
    control_ok = control["classification"] in {"not_apply_gated", "unknown"}

    rows: List[Dict[str, Any]] = []
    for blob_str in args.blob:
        blob_path = Path(blob_str)
        if not blob_path.exists():
            rows.append(
                {
                    "blob": _rel(blob_path),
                    "blob_sha256": None,
                    "result": {"error": "missing"},
                    "classification": "invalid",
                }
            )
            continue
        sha = _sha256_file(blob_path)
        run = _run_wrapper_blob(blob_path)
        rows.append(
            {
                "blob": _rel(blob_path),
                "blob_sha256": sha,
                "result": run,
                "classification": _classify_apply_gate(run),
            }
        )

    payload = {
        "tool": "book/evidence/experiments/runtime-final-final/suites/preflight-blob-digests",
        "schema_version": SCHEMA_VERSION,
        "world_id": world_id,
        "label": args.label,
        "control": control,
        "control_ok": control_ok,
        "rows": rows,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
