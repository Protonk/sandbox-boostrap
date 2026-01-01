"""
Typed runtime models used across normalization and mapping code.

These dataclasses define the shape of runtime observations and derived cuts so
the rest of the pipeline can be explicit about inputs and outputs.

Typed records are a lightweight way to document assumptions in Python.
They help later readers understand what a "runtime event" means without chasing
dozens of JSON blobs.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

# Fixed world for this repository.
# Updated only via world baseline migrations; do not override in callers.
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
    intended_op_witnessed: Optional[bool] = None
    first_denial_op: Optional[str] = None
    first_denial_filters: Optional[List[Dict[str, Any]]] = None
    decision_path: Optional[str] = None
    runtime_status: Optional[str] = None
    errno: Optional[int] = None
    errno_name: Optional[str] = None
    policy_layers: Optional[Dict[str, Any]] = None
    tcc_confounder: Optional[Dict[str, Any]] = None
    file_confounder: Optional[Dict[str, Any]] = None
    sandbox_check_prepass: Optional[Dict[str, Any]] = None
    resource_hygiene: Optional[Dict[str, Any]] = None
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
    """Paths to the canonical runtime cut artifacts."""
    events_index: Path
    scenarios: Path
    ops: Path
    indexes: Path
    manifest: Path
    runtime_story: Optional[Path] = None


@dataclass(frozen=True)
class RuntimeRun:
    """Paths to expected/runtime inputs plus the derived runtime cut."""
    expected_matrix: Path
    runtime_results: Path
    cut: RuntimeCut
    mismatch_summary: Optional[Path] = None


@dataclass(frozen=True)
class GoldenArtifacts:
    """Paths to golden artifacts derived from runtime-checks."""
    decode_summary: Path
    expectations: Path
    traces: Path
