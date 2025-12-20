"""
Stable runtime tool/IR contract helpers.

This module centralizes:
- Versioned schemas for per-probe runtime_result payloads.
- Versioned JSONL marker parsing/stripping for tool-emitted stderr markers.
- A small compatibility window (current + previous) with a single upgrade path.

It exists to prevent regressions back into ad-hoc stderr substring inference.

Tool marker families currently recognized:
- tool:"sbpl-apply" (apply/applied/exec)
- tool:"sbpl-compile" (compile-only)
- tool:"seatbelt-callout" (optional additive evidence)
- tool:"entitlement-check" (optional additive evidence)
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Mapping, Optional, Tuple


CURRENT_RUNTIME_RESULT_SCHEMA_VERSION = 1
CURRENT_TOOL_MARKER_SCHEMA_VERSION = 2
SUPPORTED_RUNTIME_RESULT_SCHEMA_VERSIONS = {0, 1}
SUPPORTED_TOOL_MARKER_SCHEMA_VERSIONS = {0, 1, 2}

SBPL_APPLY_TOOL = "sbpl-apply"
SBPL_PREFLIGHT_TOOL = "sbpl-preflight"
SEATBELT_CALLOUT_TOOL = "seatbelt-callout"
SBPL_COMPILE_TOOL = "sbpl-compile"
ENTITLEMENT_CHECK_TOOL = "entitlement-check"
SBPL_APPLY_STAGES = {"apply", "applied", "exec"}
SBPL_PREFLIGHT_STAGES = {"preflight"}
SBPL_COMPILE_STAGES = {"compile"}

CURRENT_SBPL_APPLY_MARKER_SCHEMA_VERSION = 1
CURRENT_SBPL_PREFLIGHT_MARKER_SCHEMA_VERSION = 1
CURRENT_SEATBELT_CALLOUT_MARKER_SCHEMA_VERSION = 2
CURRENT_SBPL_COMPILE_MARKER_SCHEMA_VERSION = 1
CURRENT_ENTITLEMENT_CHECK_MARKER_SCHEMA_VERSION = 1
SUPPORTED_SBPL_APPLY_MARKER_SCHEMA_VERSIONS = {0, 1}
SUPPORTED_SBPL_PREFLIGHT_MARKER_SCHEMA_VERSIONS = {0, 1}
SUPPORTED_SEATBELT_CALLOUT_MARKER_SCHEMA_VERSIONS = {0, 1, 2}
SUPPORTED_SBPL_COMPILE_MARKER_SCHEMA_VERSIONS = {0, 1}
SUPPORTED_ENTITLEMENT_CHECK_MARKER_SCHEMA_VERSIONS = {0, 1}

_FILTER_TYPE_NAMES = {
    0: "path",
    5: "global-name",
    6: "local-name",
    26: "right-name",
    27: "preference-domain",
}


def _parse_json_object(line: str) -> Optional[Dict[str, Any]]:
    candidate = (line or "").strip()
    if not (candidate.startswith("{") and candidate.endswith("}")):
        return None
    try:
        payload = json.loads(candidate)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def marker_schema_version(marker: Mapping[str, Any]) -> int:
    value = marker.get("marker_schema_version")
    return value if isinstance(value, int) else 0


def extract_sbpl_apply_markers(stderr_raw: Optional[str]) -> List[Dict[str, Any]]:
    markers: List[Dict[str, Any]] = []
    for line in (stderr_raw or "").splitlines():
        payload = _parse_json_object(line)
        if not payload:
            continue
        if payload.get("tool") != SBPL_APPLY_TOOL:
            continue
        stage = payload.get("stage")
        if stage not in SBPL_APPLY_STAGES:
            continue
        ver = payload.get("marker_schema_version")
        normalized = dict(payload)
        if not isinstance(ver, int):
            normalized["marker_schema_version"] = 0
        markers.append(normalized)
    return markers


def extract_sbpl_preflight_markers(stderr_raw: Optional[str]) -> List[Dict[str, Any]]:
    markers: List[Dict[str, Any]] = []
    for line in (stderr_raw or "").splitlines():
        payload = _parse_json_object(line)
        if not payload:
            continue
        if payload.get("tool") != SBPL_PREFLIGHT_TOOL:
            continue
        stage = payload.get("stage")
        if stage not in SBPL_PREFLIGHT_STAGES:
            continue
        ver = payload.get("marker_schema_version")
        normalized = dict(payload)
        if not isinstance(ver, int):
            normalized["marker_schema_version"] = 0
        markers.append(normalized)
    return markers


def extract_sbpl_compile_markers(stderr_raw: Optional[str]) -> List[Dict[str, Any]]:
    markers: List[Dict[str, Any]] = []
    for line in (stderr_raw or "").splitlines():
        payload = _parse_json_object(line)
        if not payload:
            continue
        if payload.get("tool") != SBPL_COMPILE_TOOL:
            continue
        stage = payload.get("stage")
        if stage not in SBPL_COMPILE_STAGES:
            continue
        ver = payload.get("marker_schema_version")
        normalized = dict(payload)
        if not isinstance(ver, int):
            normalized["marker_schema_version"] = 0
        markers.append(normalized)
    return markers


def filter_type_name(filter_type: Any) -> str:
    if isinstance(filter_type, int):
        name = _FILTER_TYPE_NAMES.get(filter_type)
        if name:
            return name
    return "unknown"


def _maybe_bool(value: Any) -> Optional[bool]:
    return value if isinstance(value, bool) else None


def _maybe_int(value: Any) -> Optional[int]:
    return value if isinstance(value, int) else None


def _maybe_str(value: Any) -> Optional[str]:
    return value if isinstance(value, str) else None


def upgrade_seatbelt_callout_marker(marker: Mapping[str, Any]) -> Dict[str, Any]:
    """
    Normalize seatbelt-callout marker dicts to the current schema shape.

    Legacy markers (schema < 2) predate:
    - no_report/no_report_reason
    - filter_type_name
    - check_type/varargs_count
    - token_status/token_mach_kr
    """

    upgraded: Dict[str, Any] = dict(marker or {})
    ver = marker_schema_version(upgraded)
    upgraded["marker_schema_version"] = ver

    ftype = upgraded.get("filter_type")
    if not isinstance(ftype, int):
        ftype = None
    upgraded["filter_type"] = ftype
    upgraded["filter_type_name"] = _maybe_str(upgraded.get("filter_type_name")) or filter_type_name(ftype)

    upgraded["check_type"] = _maybe_int(upgraded.get("check_type"))
    upgraded["varargs_count"] = _maybe_int(upgraded.get("varargs_count"))

    no_report = _maybe_bool(upgraded.get("no_report"))
    upgraded["no_report"] = no_report
    no_report_reason = _maybe_str(upgraded.get("no_report_reason"))
    if no_report_reason is None and ver < CURRENT_SEATBELT_CALLOUT_MARKER_SCHEMA_VERSION:
        no_report_reason = "legacy"
    upgraded["no_report_reason"] = no_report_reason

    upgraded["token_status"] = _maybe_str(upgraded.get("token_status"))
    upgraded["token_mach_kr"] = _maybe_int(upgraded.get("token_mach_kr"))

    upgraded["argument"] = upgraded.get("argument") if isinstance(upgraded.get("argument"), str) else None

    return upgraded


def extract_seatbelt_callout_markers(stderr_raw: Optional[str]) -> List[Dict[str, Any]]:
    markers: List[Dict[str, Any]] = []
    for line in (stderr_raw or "").splitlines():
        payload = _parse_json_object(line)
        if not payload:
            continue
        if payload.get("tool") != SEATBELT_CALLOUT_TOOL:
            continue
        ver = payload.get("marker_schema_version")
        normalized = dict(payload)
        if not isinstance(ver, int):
            normalized["marker_schema_version"] = 0
        markers.append(upgrade_seatbelt_callout_marker(normalized))
    return markers


def extract_entitlement_check_markers(stderr_raw: Optional[str]) -> List[Dict[str, Any]]:
    markers: List[Dict[str, Any]] = []
    for line in (stderr_raw or "").splitlines():
        payload = _parse_json_object(line)
        if not payload:
            continue
        if payload.get("tool") != ENTITLEMENT_CHECK_TOOL:
            continue
        ver = payload.get("marker_schema_version")
        normalized = dict(payload)
        if not isinstance(ver, int):
            normalized["marker_schema_version"] = 0
        markers.append(normalized)
    return markers


def strip_tool_markers(stderr_raw: Optional[str]) -> Optional[str]:
    """
    Remove tool JSONL markers from stderr.

    Tool markers are inputs to classification and normalization, not part of the
    canonical stderr payload stored in normalized IR.
    """

    if stderr_raw is None:
        return None
    if stderr_raw == "":
        return ""

    kept: List[str] = []
    for line in stderr_raw.splitlines():
        payload = _parse_json_object(line)
        if payload and payload.get("tool") == SBPL_APPLY_TOOL and payload.get("stage") in SBPL_APPLY_STAGES:
            continue
        if payload and payload.get("tool") == SBPL_PREFLIGHT_TOOL and payload.get("stage") in SBPL_PREFLIGHT_STAGES:
            continue
        if payload and payload.get("tool") == SEATBELT_CALLOUT_TOOL:
            continue
        if payload and payload.get("tool") == ENTITLEMENT_CHECK_TOOL:
            continue
        if payload and payload.get("tool") == SBPL_COMPILE_TOOL and payload.get("stage") in SBPL_COMPILE_STAGES:
            continue
        kept.append(line)

    if not kept:
        return ""
    return "\n".join(kept) + ("\n" if stderr_raw.endswith("\n") else "")


def _first_marker(markers: List[Dict[str, Any]], stage: str) -> Optional[Dict[str, Any]]:
    for marker in markers:
        if marker.get("stage") == stage:
            return marker
    return None


def _infer_failure_from_markers(sbpl_apply_markers: List[Dict[str, Any]]) -> Tuple[Optional[str], Optional[str], Optional[int]]:
    """
    Infer failure_stage/failure_kind from sbpl-apply marker streams.

    This is used as an upgrade fallback when a runner did not populate
    failure_stage/failure_kind but tool markers are present.
    """

    apply_marker = _first_marker(sbpl_apply_markers, "apply")
    if apply_marker:
        rc = apply_marker.get("rc")
        if isinstance(rc, int) and rc != 0:
            api = apply_marker.get("api")
            err_class = apply_marker.get("err_class")
            if err_class == "already_sandboxed":
                return "apply", "apply_already_sandboxed", apply_marker.get("errno") if isinstance(apply_marker.get("errno"), int) else None
            kind = f"{api}_failed" if isinstance(api, str) and api else "apply_failed"
            return "apply", kind, apply_marker.get("errno") if isinstance(apply_marker.get("errno"), int) else None

    exec_marker = _first_marker(sbpl_apply_markers, "exec")
    if exec_marker:
        rc = exec_marker.get("rc")
        if isinstance(rc, int) and rc != 0:
            observed_errno = exec_marker.get("errno") if isinstance(exec_marker.get("errno"), int) else None
            if observed_errno == 1 and _first_marker(sbpl_apply_markers, "applied") is not None:
                return "bootstrap", "bootstrap_deny_process_exec", observed_errno
            return "bootstrap", "bootstrap_exec_failed", observed_errno

    return None, None, None


def _infer_apply_report_from_legacy_stderr(stderr_raw: Optional[str]) -> Optional[Dict[str, Any]]:
    """
    Best-effort legacy inference for apply-stage failures when markers are absent.

    This is intentionally narrow and tagged as brittle via err_class_source.
    """

    if not stderr_raw:
        return None
    for line in stderr_raw.splitlines():
        if "sandbox_init failed:" in line:
            errbuf = line.split("sandbox_init failed:", 1)[-1].strip() or None
            err_class, source = classify_apply_err_class("sandbox_init", None, 1 if "Operation not permitted" in line else None, errbuf)
            return {
                "api": "sandbox_init",
                "rc": None,
                "errno": 1 if "Operation not permitted" in line else None,
                "errbuf": errbuf,
                "err_class": err_class,
                "err_class_source": f"legacy_stderr_regex:{source}",
            }
        if line.startswith("sandbox_apply:") or "sandbox_apply: " in line:
            errbuf = line.split("sandbox_apply:", 1)[-1].strip() or None
            err_class, source = classify_apply_err_class("sandbox_apply", None, 1 if "Operation not permitted" in line else None, errbuf)
            return {
                "api": "sandbox_apply",
                "rc": None,
                "errno": 1 if "Operation not permitted" in line else None,
                "errbuf": errbuf,
                "err_class": err_class,
                "err_class_source": f"legacy_stderr_regex:{source}",
            }
    return None


def classify_apply_err_class(api: Optional[str], rc: Any, err: Any, errbuf: Any) -> Tuple[Optional[str], Optional[str]]:
    """
    Classify apply errors into a small, stable err_class enum.

    This intentionally admits brittle sources (e.g., errbuf regex) but records
    them explicitly via err_class_source so consumers can treat them as such.
    """

    if isinstance(rc, int) and rc == 0:
        return "ok", "none"

    if api == "sandbox_init" and isinstance(errbuf, str):
        lower = errbuf.lower()
        if "already" in lower and "sandbox" in lower:
            return "already_sandboxed", "errbuf_regex"

    if err == 1:
        return "errno_eperm", "errno_only"
    if err == 13:
        return "errno_eacces", "errno_only"
    if isinstance(err, int) and err != 0:
        return "errno_other", "errno_only"

    if isinstance(errbuf, str) and errbuf:
        return "unknown", "errbuf_present"
    return "unknown", "none"


def derive_apply_report_from_markers(sbpl_apply_markers: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    apply_marker = _first_marker(sbpl_apply_markers, "apply")
    if not apply_marker:
        return None
    report: Dict[str, Any] = {
        "api": apply_marker.get("api"),
        "rc": apply_marker.get("rc"),
        "errno": apply_marker.get("errno"),
        "errbuf": apply_marker.get("errbuf"),
        "err_class": apply_marker.get("err_class"),
        "err_class_source": apply_marker.get("err_class_source"),
    }
    if report.get("err_class") is None:
        err_class, source = classify_apply_err_class(
            report.get("api"),
            report.get("rc"),
            report.get("errno"),
            report.get("errbuf"),
        )
        report["err_class"] = err_class
        report["err_class_source"] = source
    return report


def upgrade_runtime_result(runtime_result: Mapping[str, Any], stderr_raw: Optional[str]) -> Dict[str, Any]:
    """
    Upgrade a per-probe runtime_result to the current schema version.
    """

    incoming = dict(runtime_result or {})
    version = incoming.get("runtime_result_schema_version")
    if version is None:
        version = 0
    if not isinstance(version, int) or version not in SUPPORTED_RUNTIME_RESULT_SCHEMA_VERSIONS:
        raise ValueError(f"unsupported runtime_result_schema_version: {version!r}")

    sbpl_markers = extract_sbpl_apply_markers(stderr_raw)
    seatbelt_markers = extract_seatbelt_callout_markers(stderr_raw)
    entitlement_markers = extract_entitlement_check_markers(stderr_raw)

    # v0 -> v1 is additive: add explicit schema_version and normalize the optional attachments.
    upgraded: Dict[str, Any] = dict(incoming)
    upgraded["runtime_result_schema_version"] = CURRENT_RUNTIME_RESULT_SCHEMA_VERSION
    if not isinstance(upgraded.get("tool_marker_schema_version"), int):
        upgraded["tool_marker_schema_version"] = CURRENT_TOOL_MARKER_SCHEMA_VERSION

    apply_report = upgraded.get("apply_report")
    if apply_report is None and sbpl_markers:
        apply_report = derive_apply_report_from_markers(sbpl_markers)
        upgraded["apply_report"] = apply_report
    if apply_report is None and not sbpl_markers:
        legacy = _infer_apply_report_from_legacy_stderr(stderr_raw)
        if legacy is not None:
            upgraded["apply_report"] = legacy
            apply_report = legacy
            if upgraded.get("failure_stage") is None:
                api = legacy.get("api") if isinstance(legacy, dict) else None
                err_class = legacy.get("err_class") if isinstance(legacy, dict) else None
                if err_class == "already_sandboxed":
                    upgraded["failure_stage"] = "apply"
                    upgraded["failure_kind"] = "apply_already_sandboxed"
                else:
                    upgraded["failure_stage"] = "apply"
                    upgraded["failure_kind"] = f"{api}_failed" if isinstance(api, str) and api else "apply_failed"

    if isinstance(apply_report, dict):
        apply_report = dict(apply_report)
        err_class = apply_report.get("err_class")
        err_class_source = apply_report.get("err_class_source")
        if err_class is None or err_class_source is None:
            inferred, source = classify_apply_err_class(
                apply_report.get("api"),
                apply_report.get("rc"),
                apply_report.get("errno"),
                apply_report.get("errbuf"),
            )
            apply_report.setdefault("err_class", inferred)
            apply_report.setdefault("err_class_source", source)
        upgraded["apply_report"] = apply_report

    if (upgraded.get("failure_stage") is None or upgraded.get("failure_kind") is None) and sbpl_markers:
        stage, kind, _errno = _infer_failure_from_markers(sbpl_markers)
        if stage is not None:
            upgraded.setdefault("failure_stage", stage)
            upgraded.setdefault("failure_kind", kind)

    existing_callouts = upgraded.get("seatbelt_callouts")
    if isinstance(existing_callouts, list):
        normalized_callouts: List[Dict[str, Any]] = []
        for entry in existing_callouts:
            if isinstance(entry, Mapping):
                normalized_callouts.append(upgrade_seatbelt_callout_marker(entry))
        upgraded["seatbelt_callouts"] = normalized_callouts or None

    if upgraded.get("seatbelt_callouts") is None and seatbelt_markers:
        upgraded["seatbelt_callouts"] = seatbelt_markers

    existing_entitlements = upgraded.get("entitlement_checks")
    if isinstance(existing_entitlements, list):
        normalized_entitlements: List[Dict[str, Any]] = []
        for entry in existing_entitlements:
            if isinstance(entry, Mapping):
                normalized_entitlements.append(dict(entry))
        upgraded["entitlement_checks"] = normalized_entitlements or None

    if upgraded.get("entitlement_checks") is None and entitlement_markers:
        upgraded["entitlement_checks"] = entitlement_markers

    return upgraded


def assert_no_tool_markers_in_stderr(stderr_canonical: Optional[str]) -> None:
    """
    Guardrail: canonical stderr must not contain tool JSONL marker lines.
    """

    for line in (stderr_canonical or "").splitlines():
        payload = _parse_json_object(line)
        if not payload:
            continue
        tool = payload.get("tool")
        if tool in {SBPL_APPLY_TOOL, SBPL_PREFLIGHT_TOOL, SEATBELT_CALLOUT_TOOL, SBPL_COMPILE_TOOL, ENTITLEMENT_CHECK_TOOL}:
            raise AssertionError(f"canonical stderr contains tool marker: {tool}")
