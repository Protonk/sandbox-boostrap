"""Enforcement detail helpers for PolicyWitness output + observer reports."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Optional

from book.api import path_utils
from book.api.witness import observer
from book.api.witness.models import EnforcementDetail, ProbeResult
from book.api.witness.paths import REPO_ROOT


def _extract_result(stdout_json: Optional[Dict[str, object]]) -> Dict[str, object]:
    if not isinstance(stdout_json, dict):
        return {}
    result = stdout_json.get("result")
    return result if isinstance(result, dict) else {}


def _extract_data(stdout_json: Optional[Dict[str, object]]) -> Dict[str, object]:
    if not isinstance(stdout_json, dict):
        return {}
    data = stdout_json.get("data")
    return data if isinstance(data, dict) else {}


def _observer_report_from_meta(meta: Optional[Dict[str, object]]) -> Optional[Dict[str, object]]:
    if not isinstance(meta, dict):
        return None
    report = meta.get("report")
    return report if isinstance(report, dict) else None


def _load_observer_report_from_meta(meta: Optional[Dict[str, object]]) -> Optional[Dict[str, object]]:
    if not isinstance(meta, dict):
        return None
    report = _observer_report_from_meta(meta)
    if report is not None:
        return report
    log_path = meta.get("log_path")
    if isinstance(log_path, str):
        path = path_utils.ensure_absolute(Path(log_path), REPO_ROOT)
        return observer.load_observer_report(path)
    return None


def _extract_observed_deny(
    observer_report: Optional[Dict[str, object]],
    stdout_json: Optional[Dict[str, object]],
) -> Optional[bool]:
    if isinstance(observer_report, dict):
        data = observer_report.get("data")
        if isinstance(data, dict) and isinstance(data.get("observed_deny"), bool):
            return data.get("observed_deny")
    data = _extract_data(stdout_json)
    for key in ("log_observer_observed_deny", "log_capture_observed_deny"):
        value = data.get(key)
        if isinstance(value, bool):
            return value
    return None


def _extract_observer_predicate(
    observer_report: Optional[Dict[str, object]],
    stdout_json: Optional[Dict[str, object]],
) -> Optional[str]:
    if isinstance(observer_report, dict):
        data = observer_report.get("data")
        if isinstance(data, dict) and isinstance(data.get("predicate"), str):
            return data.get("predicate")
    data = _extract_data(stdout_json)
    value = data.get("log_observer_predicate")
    return value if isinstance(value, str) else None


def _extract_layer_attribution(
    observer_report: Optional[Dict[str, object]],
    stdout_json: Optional[Dict[str, object]],
) -> Optional[Dict[str, object]]:
    if isinstance(observer_report, dict):
        data = observer_report.get("data")
        if isinstance(data, dict) and isinstance(data.get("layer_attribution"), dict):
            return data.get("layer_attribution")
    data = _extract_data(stdout_json)
    attr = data.get("layer_attribution")
    if isinstance(attr, dict):
        return attr
    witness = data.get("witness")
    if isinstance(witness, dict) and isinstance(witness.get("layer_attribution"), dict):
        return witness.get("layer_attribution")
    return None


def _format_attribution(layer_attribution: Optional[Dict[str, object]], observed_deny: Optional[bool]) -> tuple[str, str]:
    if isinstance(layer_attribution, dict):
        seatbelt = layer_attribution.get("seatbelt")
        if isinstance(seatbelt, str):
            return seatbelt, "mapped"
        return json.dumps(layer_attribution, sort_keys=True), "mapped"
    if observed_deny is True:
        return "observer_only", "mapped"
    return "unknown", "hypothesis"


def enforcement_detail(
    *,
    stdout_json: Optional[Dict[str, object]] = None,
    observer_report: Optional[Dict[str, object]] = None,
) -> EnforcementDetail:
    result = _extract_result(stdout_json)
    normalized_outcome = result.get("normalized_outcome") if isinstance(result.get("normalized_outcome"), str) else None
    errno = result.get("errno") if isinstance(result.get("errno"), int) else None

    observed_deny = _extract_observed_deny(observer_report, stdout_json)
    observer_predicate = _extract_observer_predicate(observer_report, stdout_json)
    layer_attr = _extract_layer_attribution(observer_report, stdout_json)
    attribution, attribution_tier = _format_attribution(layer_attr, observed_deny)

    limits = []
    if stdout_json is None:
        limits.append("probe_response_missing")
    if normalized_outcome is None:
        limits.append("normalized_outcome_missing")
    if observer_report is None:
        limits.append("observer_report_missing")
    if observed_deny is None:
        limits.append("observed_deny_missing")
    if attribution == "observer_only":
        limits.append("observer_only_attribution")

    return EnforcementDetail(
        normalized_outcome=normalized_outcome,
        errno=errno,
        observed_deny=observed_deny,
        attribution=attribution,
        attribution_tier=attribution_tier,
        observer_predicate=observer_predicate,
        limits=limits,
    )


def enforcement_detail_from_probe_result(result: ProbeResult) -> EnforcementDetail:
    observer_report = _load_observer_report_from_meta(result.observer)
    return enforcement_detail(stdout_json=result.stdout_json, observer_report=observer_report)
