"""
Derived runtime projections.

These helpers build secondary views from normalized runtime events without
upgrading them into semantic claims or influencing failure_stage/failure_kind.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from book.api.runtime.core import models


@dataclass
class CalloutVsSyscallRow:
    world_id: str
    profile_id: str
    scenario_id: str
    operation: str
    target: Optional[str]
    argument: Optional[str]
    argument_sha256: Optional[str]
    syscall_status: Optional[str]
    syscall_errno: Optional[int]
    callout_stage: Optional[str]
    callout_decision: Optional[str]
    callout_rc: Optional[int]
    callout_errno: Optional[int]
    callout_no_report: Optional[bool]
    callout_no_report_reason: Optional[str]
    category: str


@dataclass
class CalloutOracleRow:
    world_id: str
    profile_id: str
    scenario_id: str
    expectation_id: Optional[str]
    operation: str
    target: Optional[str]
    argument: Optional[str]
    argument_sha256: Optional[str]
    callout_stage: Optional[str]
    callout_decision: Optional[str]
    callout_rc: Optional[int]
    callout_errno: Optional[int]
    callout_no_report: Optional[bool]
    callout_no_report_reason: Optional[str]
    callout_filter_type: Optional[int]
    callout_filter_type_name: Optional[str]
    callout_check_type: Optional[int]
    callout_varargs_count: Optional[int]
    callout_token_status: Optional[str]
    callout_token_mach_kr: Optional[int]
    failure_stage: Optional[str]
    failure_kind: Optional[str]
    result_source: str
    result_tier: str


def _sha256_utf8(s: Optional[str]) -> Optional[str]:
    if not s:
        return None
    h = hashlib.sha256()
    h.update(s.encode("utf-8", errors="surrogatepass"))
    return h.hexdigest()


def _pick_best_callout(
    callouts: Iterable[Mapping[str, Any]],
    operation: str,
    argument: Optional[str],
    stage_preference: Optional[List[str]] = None,
) -> Optional[Mapping[str, Any]]:
    candidates: List[Mapping[str, Any]] = []
    for marker in callouts or []:
        if marker.get("operation") != operation:
            continue
        if argument is not None and marker.get("argument") != argument:
            continue
        candidates.append(marker)
    if not candidates:
        return None

    pref = stage_preference or ["pre_syscall", "preflight", "post_apply", "bootstrap_exec"]
    by_stage = {s: i for i, s in enumerate(pref)}
    return sorted(candidates, key=lambda m: by_stage.get(str(m.get("stage")), 999))[0]


def _syscall_category(syscall_status: Optional[str], errno: Optional[int]) -> Tuple[bool, bool]:
    ok = syscall_status == "success"
    eperm = (not ok) and errno == 1
    return ok, eperm


def build_callout_vs_syscall(
    observations: Iterable[models.RuntimeObservation],
    stage_preference: Optional[List[str]] = None,
    include_non_probe: bool = False,
) -> Dict[str, Any]:
    """
    Build a callout-vs-syscall comparison table from normalized observations.

    This projection is intentionally a derived view only:
    - it never changes failure_stage/failure_kind
    - it treats callouts as additive evidence, not a semantic oracle
    """

    rows: List[CalloutVsSyscallRow] = []
    counts: Dict[str, int] = {}

    for obs in observations:
        failure_stage = obs.failure_stage
        if not include_non_probe and failure_stage not in (None, "probe"):
            continue

        callouts = obs.seatbelt_callouts or []
        argument = obs.target
        chosen = _pick_best_callout(callouts, obs.operation, argument, stage_preference=stage_preference)

        syscall_ok, syscall_eperm = _syscall_category(obs.runtime_status, obs.errno)

        if not chosen:
            category = "no_callout"
            row = CalloutVsSyscallRow(
                world_id=obs.world_id,
                profile_id=obs.profile_id,
                scenario_id=obs.scenario_id,
                operation=obs.operation,
                target=obs.target,
                argument=argument,
                argument_sha256=_sha256_utf8(argument),
                syscall_status=obs.runtime_status,
                syscall_errno=obs.errno,
                callout_stage=None,
                callout_decision=None,
                callout_rc=None,
                callout_errno=None,
                callout_no_report=None,
                callout_no_report_reason=None,
                category=category,
            )
            rows.append(row)
            counts[category] = counts.get(category, 0) + 1
            continue

        decision = chosen.get("decision")
        callout_rc = chosen.get("rc") if isinstance(chosen.get("rc"), int) else None
        callout_errno = chosen.get("errno") if isinstance(chosen.get("errno"), int) else None
        callout_no_report = chosen.get("no_report") if isinstance(chosen.get("no_report"), bool) else None
        callout_no_report_reason = chosen.get("no_report_reason") if isinstance(chosen.get("no_report_reason"), str) else None

        if decision == "error":
            category = "callout_error"
        elif decision == "allow" and syscall_ok:
            category = "agree_allow"
        elif decision == "deny" and syscall_eperm:
            category = "agree_deny"
        elif decision == "deny" and syscall_ok:
            category = "callout_deny_syscall_ok"
        elif decision == "allow" and syscall_eperm:
            category = "callout_allow_syscall_eperm"
        elif decision in {"allow", "deny"} and not syscall_ok and not syscall_eperm:
            category = f"callout_{decision}_syscall_errno"
        else:
            category = "unclassified"

        row = CalloutVsSyscallRow(
            world_id=obs.world_id,
            profile_id=obs.profile_id,
            scenario_id=obs.scenario_id,
            operation=obs.operation,
            target=obs.target,
            argument=argument,
            argument_sha256=_sha256_utf8(argument),
            syscall_status=obs.runtime_status,
            syscall_errno=obs.errno,
            callout_stage=str(chosen.get("stage")) if chosen.get("stage") is not None else None,
            callout_decision=str(decision) if decision is not None else None,
            callout_rc=callout_rc,
            callout_errno=callout_errno,
            callout_no_report=callout_no_report,
            callout_no_report_reason=callout_no_report_reason,
            category=category,
        )
        rows.append(row)
        counts[category] = counts.get(category, 0) + 1

    meta = {
        "world_id": models.WORLD_ID,
        "generated_by": "book/api/runtime/mapping/views.py",
        "notes": "Derived view: compares seatbelt-callout markers with syscall outcomes without promoting callouts into semantics.",
    }
    return {"meta": meta, "counts": counts, "rows": [asdict(r) for r in rows]}


def _as_int(value: Any) -> Optional[int]:
    return value if isinstance(value, int) else None


def _as_str(value: Any) -> Optional[str]:
    return value if isinstance(value, str) else None


def _as_bool(value: Any) -> Optional[bool]:
    return value if isinstance(value, bool) else None


def build_callout_oracle(
    observations: Iterable[models.RuntimeObservation],
    include_blocked: bool = True,
) -> Dict[str, Any]:
    """
    Build a sandbox_check oracle lane from seatbelt-callout markers.

    This is a derived view only: it records sandbox_check decisions without
    upgrading them into syscall-level semantics.
    """

    rows: List[CalloutOracleRow] = []
    counts: Dict[str, Any] = {
        "total": 0,
        "by_decision": {},
        "by_operation": {},
        "by_stage": {},
        "by_filter_type": {},
    }

    def _bump(bucket: Dict[str, int], key: Optional[str]) -> None:
        if not key:
            return
        bucket[key] = int(bucket.get(key, 0)) + 1

    for obs in observations:
        if not include_blocked and obs.failure_stage in {"apply", "bootstrap", "preflight"}:
            continue
        callouts = obs.seatbelt_callouts or []
        for marker in callouts:
            operation = _as_str(marker.get("operation")) or obs.operation
            argument = _as_str(marker.get("argument")) or obs.target
            decision = _as_str(marker.get("decision"))
            stage = _as_str(marker.get("stage"))
            filter_type_name = _as_str(marker.get("filter_type_name"))
            filter_type = _as_int(marker.get("filter_type"))
            check_type = _as_int(marker.get("check_type"))
            varargs_count = _as_int(marker.get("varargs_count"))
            token_status = _as_str(marker.get("token_status"))
            token_mach_kr = _as_int(marker.get("token_mach_kr"))
            callout_rc = _as_int(marker.get("rc"))
            callout_errno = _as_int(marker.get("errno"))
            callout_no_report = _as_bool(marker.get("no_report"))
            callout_no_report_reason = _as_str(marker.get("no_report_reason"))

            rows.append(
                CalloutOracleRow(
                    world_id=obs.world_id,
                    profile_id=obs.profile_id,
                    scenario_id=obs.scenario_id,
                    expectation_id=obs.expectation_id,
                    operation=operation,
                    target=obs.target,
                    argument=argument,
                    argument_sha256=_sha256_utf8(argument),
                    callout_stage=stage,
                    callout_decision=decision,
                    callout_rc=callout_rc,
                    callout_errno=callout_errno,
                    callout_no_report=callout_no_report,
                    callout_no_report_reason=callout_no_report_reason,
                    callout_filter_type=filter_type,
                    callout_filter_type_name=filter_type_name,
                    callout_check_type=check_type,
                    callout_varargs_count=varargs_count,
                    callout_token_status=token_status,
                    callout_token_mach_kr=token_mach_kr,
                    failure_stage=obs.failure_stage,
                    failure_kind=obs.failure_kind,
                    result_source="oracle_sandbox_check",
                    result_tier="runtime_oracle",
                )
            )

            counts["total"] += 1
            _bump(counts["by_decision"], decision)
            _bump(counts["by_operation"], operation)
            _bump(counts["by_stage"], stage)
            _bump(counts["by_filter_type"], filter_type_name or (str(filter_type) if filter_type is not None else None))

    meta = {
        "world_id": models.WORLD_ID,
        "generated_by": "book/api/runtime/mapping/views.py",
        "schema_version": "runtime-callout-oracle.v0.1",
        "status": "partial",
        "notes": "Derived view: sandbox_check (seatbelt-callout) oracle lane; decisions are not syscall outcomes.",
    }
    return {"meta": meta, "counts": counts, "rows": [asdict(r) for r in rows]}
