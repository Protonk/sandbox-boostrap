"""Wrapper for the sb_api_validator sandbox_check oracle."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Dict, Optional, Tuple

from book.api import exec_record, path_utils, tooling
from book.api.profile.identity import baseline_world_id
from book.api.witness.paths import REPO_ROOT, WITNESS_SB_API_VALIDATOR


_FILTER_CANONICAL_TO_TOOL = {
    "path": "PATH",
    "global-name": "GLOBAL_NAME",
    "local-name": "LOCAL_NAME",
    "appleevent-destination": "APPLEEVENT_DESTINATION",
    "right-name": "RIGHT_NAME",
    "preference-domain": "PREFERENCE_DOMAIN",
    "kext-bundle-id": "KEXT_BUNDLE_ID",
    "info-type": "INFO_TYPE",
    "notification-name": "NOTIFICATION",
    "xpc-service-name": "XPC_SERVICE_NAME",
    "nvram-variable": "NVRAM_VARIABLE",
    "ipc-posix-name": "POSIX_IPC_NAME",
    "iokit-connection": "IOKIT_CONNECTION",
    "sysctl-name": "SYSCTL_NAME",
}


@lru_cache(maxsize=1)
def _load_ops_vocab() -> set[str]:
    ops_path = Path("book/integration/carton/bundle/relationships/mappings/vocab/ops.json")
    ops_path = path_utils.ensure_absolute(ops_path, REPO_ROOT)
    payload = json.loads(ops_path.read_text())
    return {entry["name"] for entry in payload.get("ops", []) if isinstance(entry, dict) and "name" in entry}


@lru_cache(maxsize=1)
def _load_filters_vocab() -> set[str]:
    filters_path = Path("book/integration/carton/bundle/relationships/mappings/vocab/filters.json")
    filters_path = path_utils.ensure_absolute(filters_path, REPO_ROOT)
    payload = json.loads(filters_path.read_text())
    return {entry["name"] for entry in payload.get("filters", []) if isinstance(entry, dict) and "name" in entry}


def _normalize_filter_type(filter_type: str) -> Tuple[str, Optional[str]]:
    if not filter_type:
        raise ValueError("filter_type is required")
    if filter_type.isdigit():
        value = int(filter_type)
        if value < 0 or value > 18:
            raise ValueError(f"filter_type out of range: {filter_type}")
        return filter_type, None

    canonical = filter_type.strip().lower().replace("_", "-")
    if canonical in _FILTER_CANONICAL_TO_TOOL:
        return _FILTER_CANONICAL_TO_TOOL[canonical], canonical

    upper = filter_type.strip().upper()
    for canon, tool in _FILTER_CANONICAL_TO_TOOL.items():
        if upper == tool:
            return tool, canon
    raise ValueError(f"unsupported filter_type: {filter_type}")


def _validate_operation(operation: str) -> None:
    ops = _load_ops_vocab()
    if operation not in ops:
        raise ValueError(f"operation not in ops vocab: {operation}")


def _validate_filter_canonical(canonical: Optional[str]) -> None:
    if canonical is None:
        return
    filters = _load_filters_vocab()
    if canonical not in filters:
        raise ValueError(f"filter_type not in filters vocab: {canonical}")


def run_sb_api_validator(
    *,
    pid: int,
    operation: Optional[str] = None,
    filter_type: Optional[str] = None,
    filter_value: Optional[str] = None,
    extra: Optional[str] = None,
    timeout_s: Optional[float] = None,
) -> Dict[str, object]:
    if not WITNESS_SB_API_VALIDATOR.exists():
        rel = path_utils.to_repo_relative(WITNESS_SB_API_VALIDATOR, REPO_ROOT)
        raise FileNotFoundError(f"sb_api_validator missing: {rel}")

    cmd = [str(WITNESS_SB_API_VALIDATOR), "--json", str(pid)]
    canonical_filter = None
    if operation:
        _validate_operation(operation)
        cmd.append(operation)
        if filter_type:
            normalized, canonical_filter = _normalize_filter_type(filter_type)
            _validate_filter_canonical(canonical_filter)
            cmd.append(normalized)
            if filter_value:
                cmd.append(filter_value)
                if extra:
                    cmd.append(extra)

    record = exec_record.run_command(cmd, timeout_s=timeout_s, repo_root=REPO_ROOT)
    stdout_json = exec_record.maybe_parse_json(record.get("stdout", ""))
    payload: Dict[str, object] = {
        "world_id": baseline_world_id(REPO_ROOT),
        "entrypoint": path_utils.to_repo_relative(WITNESS_SB_API_VALIDATOR, REPO_ROOT),
        "runner_info": tooling.runner_info(WITNESS_SB_API_VALIDATOR, repo_root=REPO_ROOT, entrypoint="sb_api_validator"),
        "stage": "operation",
        "lane": "oracle",
        "pid": pid,
        "operation": operation,
        "filter_type": filter_type,
        "filter_value": filter_value,
        "extra": extra,
        **record,
    }
    if stdout_json is not None:
        payload["stdout_json"] = stdout_json
    else:
        payload["stdout_json_error"] = "stdout_json_missing"
    return payload
