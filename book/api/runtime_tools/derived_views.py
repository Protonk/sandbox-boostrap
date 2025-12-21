"""
Derived runtime projections.

These helpers build secondary views from normalized runtime events without
upgrading them into semantic claims or influencing failure_stage/failure_kind.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from book.api.runtime_tools import observations as runtime_observations


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


def callout_vs_syscall_comparison(
    observations: Iterable[runtime_observations.RuntimeObservation],
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
        "world_id": runtime_observations.WORLD_ID,
        "generated_by": "book/api/runtime_tools/derived_views.py",
        "notes": "Derived view: compares seatbelt-callout markers with syscall outcomes without promoting callouts into semantics.",
    }
    return {"meta": meta, "counts": counts, "rows": [asdict(r) for r in rows]}
