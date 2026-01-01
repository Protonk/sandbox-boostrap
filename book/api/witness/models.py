"""Data models for the Witness API (PolicyWitness tool surface)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence


@dataclass(frozen=True)
class ProbeRequest:
    """Request for a single PolicyWitness probe via `xpc run`."""

    probe_id: str
    profile_id: Optional[str] = None
    probe_args: Sequence[str] = ()
    plan_id: str = "witness:probe"
    row_id: Optional[str] = None
    correlation_id: Optional[str] = None
    capture_sandbox_logs: bool = False
    timeout_s: Optional[float] = None
    service_id: Optional[str] = None

    def validate(self) -> None:
        if not self.profile_id and not self.service_id:
            raise ValueError("probe requires profile_id or service_id")
        if self.profile_id and self.service_id:
            raise ValueError("probe accepts only one of profile_id or service_id")
        if not self.probe_id:
            raise ValueError("probe_id is required")


@dataclass
class ProbeResult:
    """Normalized probe result plus observer metadata."""

    world_id: str
    entrypoint: str
    profile_id: Optional[str]
    service_id: Optional[str]
    probe_id: str
    probe_args: List[str]
    plan_id: str
    row_id: Optional[str]
    correlation_id: Optional[str]
    capture_sandbox_logs: bool
    started_at_unix_s: float
    finished_at_unix_s: float
    duration_s: float
    command: List[str]
    exit_code: Optional[int]
    stdout: str
    stderr: str
    log_path: Optional[str]
    observer: Optional[Dict[str, object]]
    observer_log_path: Optional[str]
    observer_status: str
    probe_timeout_s: float
    probe_error: Optional[str]
    runner_info: Optional[Dict[str, object]] = None
    bundle: Optional[Dict[str, object]] = None
    log_write_error: Optional[str] = None
    lifecycle: Optional["LifecycleSnapshot"] = None
    record_write_error: Optional[str] = None
    stdout_json: Optional[Dict[str, object]] = None
    stdout_json_error: Optional[str] = None
    evidence_tier: str = "mapped"

    def to_json(self) -> Dict[str, object]:
        return asdict(self)


@dataclass
class LifecycleSnapshot:
    """On-demand lifecycle metadata from a probe or session."""

    profile_id: Optional[str]
    service_id: Optional[str]
    service_pid: Optional[str]
    process_name: Optional[str]
    correlation_id: Optional[str]
    plan_id: Optional[str]
    row_id: Optional[str]
    tmp_dir: Optional[str]
    file_path: Optional[str]
    evidence_tier: str = "mapped"

    def to_json(self) -> Dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class CommandSpec:
    """Command execution spec for non-PolicyWitness baselines."""

    argv: Sequence[str]
    cwd: Optional[Path] = None
    timeout_s: Optional[float] = None


@dataclass
class CommandResult:
    """Result of a command execution (none/SBPL baseline)."""

    command: List[str]
    exit_code: Optional[int]
    stdout: str
    stderr: str
    started_at_unix_s: float
    finished_at_unix_s: float
    duration_s: float
    error: Optional[str] = None
    tool_markers: Optional[Dict[str, List[Dict[str, object]]]] = None
    runner_info: Optional[Dict[str, object]] = None
    preflight: Optional[Dict[str, object]] = None
    evidence_tier: str = "mapped"

    def to_json(self) -> Dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class EntitlementAction:
    """Action to execute via PolicyWitness entitlements (xpc run)."""

    probe_id: str
    profile_id: Optional[str] = None
    probe_args: Sequence[str] = ()
    plan_id: Optional[str] = None
    row_id: Optional[str] = None
    correlation_id: Optional[str] = None
    capture_sandbox_logs: bool = False
    timeout_s: Optional[float] = None
    service_id: Optional[str] = None


@dataclass(frozen=True)
class SbplAction:
    """Action to execute under SBPL via the wrapper."""

    command: CommandSpec
    sbpl_path: Optional[Path] = None
    blob_path: Optional[Path] = None
    preflight: Optional[str] = None


@dataclass(frozen=True)
class ActionSpec:
    """Baseline comparison spec for entitlements/SBPL/none."""

    action_id: str
    entitlements: Optional[EntitlementAction] = None
    sbpl: Optional[SbplAction] = None
    none: Optional[CommandSpec] = None


@dataclass
class ComparisonReport:
    """Aggregated baseline comparison output."""

    action_id: str
    world_id: str
    results: Dict[str, Dict[str, object]]
    limits: List[str] = field(default_factory=list)
    evidence_tier: str = "mapped"

    def to_json(self) -> Dict[str, object]:
        return asdict(self)


@dataclass
class EnforcementDetail:
    """Minute enforcement detail with explicit attribution bounds."""

    normalized_outcome: Optional[str]
    errno: Optional[int]
    observed_deny: Optional[bool]
    attribution: str
    attribution_tier: str
    observer_predicate: Optional[str]
    limits: List[str]
    evidence_tier: str = "mapped"

    def to_json(self) -> Dict[str, object]:
        return asdict(self)
