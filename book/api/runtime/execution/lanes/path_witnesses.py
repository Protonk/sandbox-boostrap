"""
runtime path-witness extraction (service support).

This module builds a small, explicit "path witness" IR from bundle artifacts so
VFS canonicalization work does not have to re-parse stderr markers ad-hoc.

Responsibilities:
- Parse `F_GETPATH*` markers emitted by the file probes on stderr.
- Join those markers back to `(profile_id, scenario_id, operation, target)` so
  consumers can reason about `requested_path` vs `observed_path` mechanically.
- Emit `path_witnesses.json` as a run-scoped bundle artifact.

Non-goals / refusals:
- This module does not claim that any observed path spelling is the literal
  Seatbelt consulted; it only records what the kernel reported for an FD.
- This module does not infer semantics from missing witnesses (denied opens do
  not produce FD paths).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


PATH_WITNESS_SCHEMA_VERSION = "runtime-tools.path_witness.v0.1"
PATH_WITNESSES_SCHEMA_VERSION = "runtime-tools.path_witnesses.v0.1"


def _is_path_operation(op: Optional[str]) -> bool:
    if not op:
        return False
    return op.startswith("file-") or op in {"file-read*", "file-write*"}


def _extract_marker(stderr: Optional[str], *, label: str) -> Tuple[Optional[str], str, Optional[int]]:
    """
    Extract a single F_GETPATH-style marker from probe stderr.

    Returns (path, source, errno).
    """

    if not stderr:
        return None, "missing", None
    for line in stderr.splitlines():
        if line.startswith(f"{label}:"):
            return line.split(":", 1)[1].strip() or None, "present", None
        if line.startswith(f"{label}_ERROR:"):
            raw = line.split(":", 1)[1].strip()
            try:
                err = int(raw)
            except ValueError:
                err = None
            return None, "error", err
        if line.startswith(f"{label}_UNAVAILABLE"):
            return None, "unavailable", None
    return None, "missing", None


def _normalize_path(requested_path: Optional[str], observed_path: Optional[str]) -> Tuple[Optional[str], str]:
    if observed_path:
        return observed_path, "observed_path"
    if requested_path:
        return requested_path, "requested_path"
    return None, "missing"


def build_path_witnesses_doc(
    run_dir: Path,
    *,
    world_id: str,
    run_id: str,
    plan_id: str,
) -> Dict[str, Any]:
    records: List[Dict[str, Any]] = []

    baseline_path = run_dir / "baseline_results.json"
    if baseline_path.exists():
        baseline_doc = json.loads(baseline_path.read_text(encoding="utf-8", errors="ignore"))
        for row in baseline_doc.get("results") or []:
            op = row.get("operation")
            if not _is_path_operation(op):
                continue
            requested_path = row.get("target")
            normalized_path, normalized_source = _normalize_path(requested_path, row.get("observed_path"))
            records.append(
                {
                    "schema_version": PATH_WITNESS_SCHEMA_VERSION,
                    "lane": "baseline",
                    "profile_id": row.get("profile_id"),
                    "scenario_id": row.get("name"),
                    "operation": op,
                    "requested_path": requested_path,
                    "observed_path": row.get("observed_path"),
                    "observed_path_source": row.get("observed_path_source"),
                    "observed_path_errno": row.get("observed_path_errno"),
                    "observed_path_nofirmlink": row.get("observed_path_nofirmlink"),
                    "observed_path_nofirmlink_source": row.get("observed_path_nofirmlink_source"),
                    "observed_path_nofirmlink_errno": row.get("observed_path_nofirmlink_errno"),
                    "normalized_path": normalized_path,
                    "normalized_path_source": normalized_source,
                    "decision": row.get("status"),
                    "exit_code": row.get("exit_code"),
                    "command": row.get("command"),
                }
            )

    events_path = run_dir / "runtime_events.normalized.json"
    if events_path.exists():
        events = json.loads(events_path.read_text(encoding="utf-8", errors="ignore"))
        for row in events:
            op = row.get("operation")
            if not _is_path_operation(op):
                continue
            requested_path = row.get("target")
            stderr = row.get("stderr")

            observed, observed_src, observed_errno = _extract_marker(stderr, label="F_GETPATH")
            nofirmlink, nofirmlink_src, nofirmlink_errno = _extract_marker(stderr, label="F_GETPATH_NOFIRMLINK")
            normalized_path, normalized_source = _normalize_path(requested_path, observed)

            records.append(
                {
                    "schema_version": PATH_WITNESS_SCHEMA_VERSION,
                    "lane": "scenario",
                    "profile_id": row.get("profile_id"),
                    "scenario_id": row.get("scenario_id"),
                    "operation": op,
                    "requested_path": requested_path,
                    "observed_path": observed,
                    "observed_path_source": f"probe_fgetpath:{observed_src}",
                    "observed_path_errno": observed_errno,
                    "observed_path_nofirmlink": nofirmlink,
                    "observed_path_nofirmlink_source": f"probe_fgetpath_nofirmlink:{nofirmlink_src}",
                    "observed_path_nofirmlink_errno": nofirmlink_errno,
                    "normalized_path": normalized_path,
                    "normalized_path_source": normalized_source,
                    "decision": row.get("actual"),
                    "errno": row.get("errno"),
                    "failure_stage": row.get("failure_stage"),
                    "failure_kind": row.get("failure_kind"),
                    "command": row.get("command"),
                }
            )

    return {
        "schema_version": PATH_WITNESSES_SCHEMA_VERSION,
        "world_id": world_id,
        "run_id": run_id,
        "plan_id": plan_id,
        "records": records,
    }

