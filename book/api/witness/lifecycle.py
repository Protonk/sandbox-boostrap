"""Lifecycle snapshot helpers for PolicyWitness probes and sessions."""

from __future__ import annotations

from typing import Dict, Optional

from book.api.witness import observer
from book.api.witness.models import LifecycleSnapshot


def _coerce_str(value: object) -> Optional[str]:
    return value if isinstance(value, str) else None


def _coerce_pid(value: object) -> Optional[str]:
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return value
    return None


def _extract_data(stdout_json: Optional[Dict[str, object]]) -> Dict[str, object]:
    if not isinstance(stdout_json, dict):
        return {}
    data = stdout_json.get("data")
    return data if isinstance(data, dict) else {}


def extract_details(stdout_json: Optional[Dict[str, object]]) -> Optional[Dict[str, object]]:
    return observer.extract_details(stdout_json)


def extract_tmp_dir(stdout_json: Optional[Dict[str, object]]) -> Optional[str]:
    details = extract_details(stdout_json)
    if details is None:
        return None
    tmp_dir = details.get("tmp_dir")
    return tmp_dir if isinstance(tmp_dir, str) else None


def extract_file_path(stdout_json: Optional[Dict[str, object]]) -> Optional[str]:
    details = extract_details(stdout_json)
    if details is None:
        return None
    file_path = details.get("file_path")
    return file_path if isinstance(file_path, str) else None


def snapshot_from_probe(
    stdout_json: Optional[Dict[str, object]],
    *,
    profile_id: Optional[str] = None,
    service_id: Optional[str] = None,
    plan_id: Optional[str] = None,
    row_id: Optional[str] = None,
) -> LifecycleSnapshot:
    data = _extract_data(stdout_json)
    details = data.get("details") if isinstance(data.get("details"), dict) else {}

    resolved_service_id = service_id or _coerce_str(data.get("service_bundle_id")) or _coerce_str(data.get("service_name"))
    resolved_plan_id = plan_id or _coerce_str(data.get("plan_id"))
    resolved_row_id = row_id or _coerce_str(data.get("row_id"))

    service_pid = observer.extract_service_pid(stdout_json) or _coerce_pid(data.get("pid"))
    process_name = (
        observer.extract_process_name(stdout_json)
        or _coerce_str(data.get("service_name"))
        or _coerce_str(data.get("process_name"))
    )
    correlation_id = observer.extract_correlation_id(stdout_json) or _coerce_str(data.get("correlation_id"))
    tmp_dir = _coerce_str(details.get("tmp_dir"))
    file_path = _coerce_str(details.get("file_path"))

    return LifecycleSnapshot(
        profile_id=profile_id,
        service_id=resolved_service_id,
        service_pid=service_pid,
        process_name=process_name,
        correlation_id=correlation_id,
        plan_id=resolved_plan_id,
        row_id=resolved_row_id,
        tmp_dir=tmp_dir,
        file_path=file_path,
    )


def snapshot_from_event(
    event: Optional[Dict[str, object]],
    *,
    profile_id: Optional[str] = None,
    service_id: Optional[str] = None,
) -> LifecycleSnapshot:
    data = _extract_data(event)
    service_pid = _coerce_pid(data.get("pid"))
    process_name = _coerce_str(data.get("service_name")) or _coerce_str(data.get("process_name"))
    correlation_id = _coerce_str(data.get("correlation_id"))
    plan_id = _coerce_str(data.get("plan_id"))
    row_id = _coerce_str(data.get("row_id"))
    resolved_service_id = service_id or _coerce_str(data.get("service_bundle_id")) or process_name

    return LifecycleSnapshot(
        profile_id=profile_id,
        service_id=resolved_service_id,
        service_pid=service_pid,
        process_name=process_name,
        correlation_id=correlation_id,
        plan_id=plan_id,
        row_id=row_id,
        tmp_dir=None,
        file_path=None,
    )


def snapshot_from_session(session: "object") -> LifecycleSnapshot:
    data = None
    if hasattr(session, "session_ready"):
        ready = getattr(session, "session_ready")
        if isinstance(ready, dict):
            data = ready.get("data")
    event = {"data": data} if isinstance(data, dict) else None
    profile_id = getattr(session, "profile_id", None)
    service_id = None
    return snapshot_from_event(event, profile_id=profile_id, service_id=service_id)
