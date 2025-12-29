from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

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
    run_id: Optional[str] = None
    expectation_id: Optional[str] = None
    operation: str = ""
    target: Optional[str] = None
    requested_path: Optional[str] = None
    observed_path: Optional[str] = None
    observed_path_source: Optional[str] = None
    normalized_path: Optional[str] = None
    normalized_path_source: Optional[str] = None
    probe_name: Optional[str] = None
    expected: Optional[str] = None
    actual: Optional[str] = None
    match: Optional[bool] = None
    primary_intent: Optional[Dict[str, Any]] = None
    reached_primary_op: Optional[bool] = None
    first_denial_op: Optional[str] = None
    first_denial_filters: Optional[List[Dict[str, Any]]] = None
    decision_path: Optional[str] = None
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
    probe_details: Optional[Dict[str, Any]] = None
    violation_summary: Optional[str] = None
    command: Optional[List[str]] = None
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    harness: Optional[str] = None
    notes: Optional[str] = None


@dataclass(frozen=True)
class RuntimeCut:
    events_index: Path
    scenarios: Path
    ops: Path
    indexes: Path
    manifest: Path
    runtime_story: Optional[Path] = None


@dataclass(frozen=True)
class RuntimeRun:
    expected_matrix: Path
    runtime_results: Path
    cut: RuntimeCut
    mismatch_summary: Optional[Path] = None


@dataclass(frozen=True)
class GoldenArtifacts:
    decode_summary: Path
    expectations: Path
    traces: Path
