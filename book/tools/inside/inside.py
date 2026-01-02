#!/usr/bin/env python3
"""
Harness sandbox detector (codex-sandbox tool).

Runs a set of sensors and returns a structured verdict about whether the
current process is sandbox-constrained.
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import datetime as dt
import json
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from book.api import exec_record, path_utils
from book.api.profile.identity import baseline_world_id
from book.api.runtime.contracts import schema as runtime_schema


RESULT_STRONG_TRUE = "strong_true"
RESULT_WEAK_TRUE = "weak_true"
RESULT_UNKNOWN = "unknown"
RESULT_WEAK_FALSE = "weak_false"
RESULT_STRONG_FALSE = "strong_false"

SENSOR_ORDER = ["S0", "S1", "S2", "S3", "S4", "S5", "S6"]

DEFAULT_POLICYWITNESS_BIN = "book/tools/witness/PolicyWitness.app/Contents/MacOS/policy-witness"
DEFAULT_POLICYWITNESS_SERVICE = "com.yourteam.policy-witness.ProbeService_minimal"
DEFAULT_MACH_CONTROL_SERVICE = "com.apple.cfprefsd.daemon"
DEFAULT_BOOTSTRAP_NAMES = ["com.apple.cfprefsd.agent", "com.apple.trustd"]
DEFAULT_SBPL_WRAPPER = "book/tools/sbpl/wrapper/wrapper"
DEFAULT_SBPL_PROFILE = "book/evidence/experiments/runtime-final-final/suites/sbpl-graph-runtime/profiles/allow_all.sb"

SANDBOX_HEADER_CANDIDATES = [
    Path("/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sandbox.h"),
    Path(
        "/Applications/Xcode.app/Contents/Developer/Platforms/"
        "MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/include/sandbox.h"
    ),
]

VENDORED_SANDBOX_CONSTANTS = {
    "SANDBOX_FILTER_GLOBAL_NAME": 2,
    "SANDBOX_FILTER_LOCAL_NAME": 3,
}


def _repo_root() -> Path:
    return path_utils.find_repo_root(Path(__file__))


def _load_libsystem() -> ctypes.CDLL:
    lib_path = ctypes.util.find_library("System") or "libSystem.B.dylib"
    return ctypes.CDLL(lib_path, use_errno=True)


def _sandbox_check(
    op: Optional[str],
    *,
    filter_type: int = 0,
    target: Optional[str] = None,
) -> Dict[str, Any]:
    lib = _load_libsystem()
    func = lib.sandbox_check
    func.restype = ctypes.c_int
    ctypes.set_errno(0)
    pid = os.getpid()
    op_bytes = op.encode() if op else None
    if target is None:
        rc = func(pid, op_bytes, filter_type)
    else:
        rc = func(pid, op_bytes, filter_type, target.encode())
    err = ctypes.get_errno()
    return {
        "pid": pid,
        "operation": op,
        "filter_type": filter_type,
        "target": target,
        "rc": rc,
        "errno": err,
    }


def _bootstrap_lookup(service_name: str) -> Dict[str, Any]:
    lib = _load_libsystem()
    record: Dict[str, Any] = {"service_name": service_name}
    try:
        bootstrap_port = ctypes.c_uint.in_dll(lib, "bootstrap_port").value
    except Exception as exc:
        record["error"] = f"bootstrap_port_missing:{exc}"
        return record
    try:
        func = lib.bootstrap_look_up
    except Exception as exc:
        record["error"] = f"bootstrap_lookup_missing:{exc}"
        return record
    func.restype = ctypes.c_int
    func.argtypes = [ctypes.c_uint, ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint)]
    ctypes.set_errno(0)
    out_port = ctypes.c_uint(0)
    kr = func(bootstrap_port, service_name.encode(), ctypes.byref(out_port))
    record["bootstrap_port"] = bootstrap_port
    record["kr"] = kr
    record["errno"] = ctypes.get_errno()
    record["port"] = out_port.value
    if out_port.value:
        try:
            mach_task_self = getattr(lib, "mach_task_self", None)
            dealloc = getattr(lib, "mach_port_deallocate", None)
            if mach_task_self and dealloc:
                dealloc.argtypes = [ctypes.c_uint, ctypes.c_uint]
                dealloc.restype = ctypes.c_int
                dealloc(mach_task_self(), out_port.value)
        except Exception:
            record["dealloc_error"] = "mach_port_deallocate_failed"
    try:
        strerror = lib.bootstrap_strerror
        strerror.restype = ctypes.c_char_p
        record["kr_text"] = strerror(kr).decode()
    except Exception:
        record["kr_text"] = None
    return record


def _load_sandbox_constants() -> Dict[str, int]:
    pattern = re.compile(r"^\s*#define\s+([A-Z0-9_]+)\s+([0-9]+)\s*$")
    hex_pattern = re.compile(r"^\s*#define\s+([A-Z0-9_]+)\s+(0x[0-9A-Fa-f]+)\s*$")
    constants: Dict[str, int] = {}
    for candidate in SANDBOX_HEADER_CANDIDATES:
        if not candidate.exists():
            continue
        try:
            for line in candidate.read_text().splitlines():
                match = pattern.match(line)
                if match:
                    constants[match.group(1)] = int(match.group(2))
                    continue
                match = hex_pattern.match(line)
                if match:
                    constants[match.group(1)] = int(match.group(2), 16)
        except Exception:
            continue
        if constants:
            constants["source_path"] = str(candidate)
            break
    return constants


def _resolve_filter_constant(
    constants: Dict[str, int],
    name: str,
) -> Tuple[Optional[int], Optional[str]]:
    value = constants.get(name)
    if isinstance(value, int):
        return value, "header"
    value = VENDORED_SANDBOX_CONSTANTS.get(name)
    if isinstance(value, int):
        return value, "vendored"
    return None, None


def _strength_from_result(result_class: str) -> str:
    if result_class.startswith("strong"):
        return "strong"
    if result_class.startswith("weak"):
        return "weak"
    return "unknown"


def _direction_from_result(result_class: str) -> Optional[bool]:
    if result_class.endswith("true"):
        return True
    if result_class.endswith("false"):
        return False
    return None


def _result_payload(result_class: str, **fields: Any) -> Dict[str, Any]:
    payload = dict(fields)
    payload["result_class"] = result_class
    payload["strength"] = _strength_from_result(result_class)
    payload["direction"] = _direction_from_result(result_class)
    return payload


def _summarize_xpc(stdout: str) -> Dict[str, Any]:
    payload = exec_record.maybe_parse_json(stdout)
    if not isinstance(payload, dict):
        return {"stdout_json": None}
    data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
    layer = data.get("layer_attribution") if isinstance(data.get("layer_attribution"), dict) else {}
    return {
        "stdout_json": payload,
        "normalized_outcome": data.get("normalized_outcome"),
        "layer_attribution": layer,
        "error": data.get("error"),
    }


def _summarize_sbpl(stderr: str) -> Dict[str, Any]:
    apply_markers = runtime_schema.extract_sbpl_apply_markers(stderr)
    preflight_markers = runtime_schema.extract_sbpl_preflight_markers(stderr)
    apply_eperm = any(marker.get("err_class") == "errno_eperm" for marker in apply_markers)
    apply_ok = any(marker.get("err_class") == "ok" for marker in apply_markers)
    return {
        "apply_markers": apply_markers,
        "preflight_markers": preflight_markers,
        "apply_eperm": apply_eperm,
        "apply_ok": apply_ok,
    }


def _resolve_exec_target(repo_root: Path, raw_path: str) -> Tuple[str, str]:
    if os.sep not in raw_path:
        resolved = shutil.which(raw_path)
        exec_path = resolved or raw_path
        return exec_path, raw_path
    abs_path = path_utils.ensure_absolute(raw_path, repo_root)
    return str(abs_path), path_utils.to_repo_relative(abs_path, repo_root)


def _sensor_s0() -> Dict[str, Any]:
    raw = _sandbox_check(None, filter_type=0)
    if raw["rc"] == 1:
        result_class = RESULT_STRONG_TRUE
        note = "sandbox_check(getpid(), NULL) rc=1"
    elif raw["rc"] == 0:
        result_class = RESULT_STRONG_FALSE
        note = "sandbox_check(getpid(), NULL) rc=0"
    else:
        result_class = RESULT_UNKNOWN
        note = "sandbox_check(getpid(), NULL) error"
    return _result_payload(result_class, **raw, note=note, evidence_tier="mapped")


def _sensor_s1(
    service_name: str,
    control_service: str,
    *,
    allow_unfiltered: bool,
    allow_vendored: bool,
) -> Dict[str, Any]:
    constants = _load_sandbox_constants()
    filter_value = None
    filter_source = None
    if allow_vendored or constants:
        filter_value, filter_source = _resolve_filter_constant(constants, "SANDBOX_FILTER_GLOBAL_NAME")
    no_report_value = constants.get("SANDBOX_CHECK_NO_REPORT") if isinstance(constants.get("SANDBOX_CHECK_NO_REPORT"), int) else None
    if filter_value is None and not allow_unfiltered:
        return _result_payload(
            RESULT_UNKNOWN,
            note="sandbox_check(mach-lookup) skipped; no filter constant and unfiltered fallback disabled",
            target=service_name,
            control=control_service,
            constants_source=constants.get("source_path"),
            evidence_tier="mapped",
        )
    filter_type = filter_value or 0
    if filter_value is None:
        filter_source = "fallback_unfiltered"
    no_report_used = False
    if filter_value is not None and no_report_value is not None:
        filter_type = filter_type | no_report_value
        no_report_used = True

    if filter_value is None:
        coarse_raw = _sandbox_check("mach-lookup", filter_type=filter_type, target=None)
        target_raw = dict(coarse_raw)
        control_raw = dict(coarse_raw)
    else:
        target_raw = _sandbox_check("mach-lookup", filter_type=filter_type, target=service_name)
        control_raw = _sandbox_check("mach-lookup", filter_type=filter_type, target=control_service)

    target_error = target_raw.get("rc") in (-1, None)
    control_error = control_raw.get("rc") in (-1, None)

    result_class = RESULT_UNKNOWN
    note = ""
    if not target_error and not control_error:
        if target_raw["rc"] != 0 and control_raw["rc"] == 0:
            result_class = RESULT_STRONG_TRUE
            note = "target denied, control allowed"
        elif target_raw["rc"] != 0 and control_raw["rc"] != 0:
            result_class = RESULT_WEAK_TRUE
            note = "target and control denied"
        elif target_raw["rc"] == 0 and control_raw["rc"] == 0:
            result_class = RESULT_STRONG_FALSE
            note = "target and control allowed"
        else:
            result_class = RESULT_WEAK_FALSE
            note = "target allowed, control denied"
    else:
        note = "sandbox_check error"

    if filter_source == "fallback_unfiltered":
        if result_class == RESULT_STRONG_TRUE:
            result_class = RESULT_WEAK_TRUE
        elif result_class == RESULT_STRONG_FALSE:
            result_class = RESULT_WEAK_FALSE
        if note:
            note = f"{note} (unfiltered)"

    return _result_payload(
        result_class,
        note=note,
        target=service_name,
        control=control_service,
        target_result=target_raw,
        control_result=control_raw,
        filter_value=filter_value,
        filter_type=filter_type,
        filter_source=filter_source,
        constants_source=constants.get("source_path"),
        no_report_available=no_report_value is not None,
        no_report_used=no_report_used,
        evidence_tier="mapped",
    )


def _sensor_s2(service_names: Iterable[str]) -> Dict[str, Any]:
    results = []
    for name in service_names:
        results.append(_bootstrap_lookup(name))

    result_class = RESULT_UNKNOWN
    note = ""
    if any(res.get("kr") == 1100 for res in results if "kr" in res):
        result_class = RESULT_STRONG_TRUE
        note = "bootstrap constrained (kr=1100)"
    elif any(res.get("kr") == 0 for res in results if "kr" in res):
        result_class = RESULT_WEAK_FALSE
        note = "bootstrap ok"
    elif all(res.get("kr") == 1102 for res in results if "kr" in res):
        result_class = RESULT_UNKNOWN
        note = "bootstrap unknown service"
    else:
        note = "bootstrap inconclusive"

    return _result_payload(
        result_class,
        note=note,
        results=results,
        evidence_tier="mapped",
    )


def _sensor_s3(
    policywitness_bin: str,
    policywitness_rel: str,
    service_name: str,
    timeout_s: float,
) -> Dict[str, Any]:
    if not Path(policywitness_bin).exists():
        return _result_payload(
            RESULT_UNKNOWN,
            note="policy-witness binary missing",
            policywitness_bin=policywitness_rel,
            service_name=service_name,
            evidence_tier="mapped",
        )

    cmd = [
        policywitness_bin,
        "xpc",
        "run",
        "--profile",
        "minimal",
        "fs_op",
        "--op",
        "stat",
        "--path-class",
        "tmp",
    ]
    record = exec_record.run_command(cmd, timeout_s=timeout_s, repo_root=_repo_root())
    summary = _summarize_xpc(record.get("stdout", ""))
    normalized = summary.get("normalized_outcome")
    layer = summary.get("layer_attribution") or {}
    error = summary.get("error") or ""

    result_class = RESULT_UNKNOWN
    note = ""
    if normalized == "xpc_error" and layer.get("other") == "xpc:openSession_failed":
        if "Sandbox restriction" in error or "error 159" in error:
            result_class = RESULT_STRONG_TRUE
            note = "xpc openSession failed with sandbox restriction"
        else:
            result_class = RESULT_UNKNOWN
            note = "xpc openSession failed without sandbox restriction"
    elif normalized == "ok":
        result_class = RESULT_WEAK_FALSE
        note = "xpc probe ok"
    elif record.get("exit_code") is not None and record.get("exit_code") != 0:
        note = "xpc probe failed"

    return _result_payload(
        result_class,
        note=note,
        policywitness_bin=policywitness_rel,
        service_name=service_name,
        record=record,
        summary=summary,
        evidence_tier="mapped",
    )


def _sensor_s4(
    wrapper_path: str,
    wrapper_rel: str,
    sbpl_path: str,
    sbpl_rel: str,
    timeout_s: float,
    include_apply: bool,
) -> Dict[str, Any]:
    if not include_apply:
        return _result_payload(
            RESULT_UNKNOWN,
            note="sbpl apply skipped",
            wrapper=wrapper_rel,
            profile=sbpl_rel,
            skipped=True,
            evidence_tier="mapped",
        )
    if not Path(wrapper_path).exists():
        return _result_payload(
            RESULT_UNKNOWN,
            note="sbpl wrapper missing",
            wrapper=wrapper_rel,
            profile=sbpl_rel,
            evidence_tier="mapped",
        )
    if not Path(sbpl_path).exists():
        return _result_payload(
            RESULT_UNKNOWN,
            note="sbpl profile missing",
            wrapper=wrapper_rel,
            profile=sbpl_rel,
            evidence_tier="mapped",
        )
    cmd = [
        wrapper_path,
        "--preflight",
        "enforce",
        "--sbpl",
        sbpl_path,
        "--",
        "/usr/bin/true",
    ]
    record = exec_record.run_command(cmd, timeout_s=timeout_s, repo_root=_repo_root())
    summary = _summarize_sbpl(record.get("stderr", ""))

    result_class = RESULT_UNKNOWN
    note = ""
    if summary.get("apply_eperm"):
        result_class = RESULT_STRONG_TRUE
        note = "apply-stage EPERM"
    elif summary.get("apply_ok"):
        result_class = RESULT_WEAK_FALSE
        note = "apply ok"
    else:
        note = "apply inconclusive"

    return _result_payload(
        result_class,
        note=note,
        wrapper=wrapper_rel,
        profile=sbpl_rel,
        record=record,
        summary=summary,
        evidence_tier="mapped",
    )


def _sensor_s5(
    log_bin: str,
    predicate: str,
    start_ts: dt.datetime,
    end_ts: dt.datetime,
    pid: int,
    include_logs: bool,
) -> Dict[str, Any]:
    if not include_logs:
        return _result_payload(
            RESULT_UNKNOWN,
            note="log corroboration skipped",
            skipped=True,
            evidence_tier="hypothesis",
        )
    fmt = "%Y-%m-%d %H:%M:%S"
    cmd = [
        log_bin,
        "show",
        "--style",
        "syslog",
        "--start",
        start_ts.strftime(fmt),
        "--end",
        end_ts.strftime(fmt),
        "--predicate",
        predicate,
    ]
    record = exec_record.run_command(cmd, timeout_s=30.0, repo_root=_repo_root())
    stdout = record.get("stdout", "")
    deny_lines = [
        line
        for line in stdout.splitlines()
        if (
            "deny(" in line
            or "forbidden-sandbox-reinit" in line
            or "mach-lookup" in line
            or "sandbox" in line.lower()
        )
    ]
    pid_tag = f"({pid})"
    pid_lines = [line for line in deny_lines if pid_tag in line]

    result_class = RESULT_UNKNOWN
    note = ""
    if record.get("exit_code") != 0:
        note = "log show failed"
    elif pid_lines:
        result_class = RESULT_WEAK_TRUE
        note = "deny lines for pid"
    else:
        note = "no pid deny lines"

    return _result_payload(
        result_class,
        note=note,
        record=record,
        deny_lines=deny_lines,
        deny_lines_pid=pid_lines,
        predicate=predicate,
        evidence_tier="hypothesis",
    )


def _sensor_s6() -> Dict[str, Any]:
    container_id = os.environ.get("APP_SANDBOX_CONTAINER_ID")
    home = os.environ.get("HOME", "")
    home_in_container = "/Library/Containers/" in home
    present = bool(container_id) or home_in_container
    result_class = RESULT_WEAK_TRUE if present else RESULT_WEAK_FALSE
    note = "app sandbox env" if present else "no app sandbox env"
    return _result_payload(
        result_class,
        note=note,
        container_id=container_id,
        home=home,
        home_in_container=home_in_container,
        evidence_tier="mapped",
        axis="app_sandbox",
    )


def _score_harness(signals: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    strong_true_all = [sid for sid, s in signals.items() if s["result_class"] == RESULT_STRONG_TRUE and sid in {"S0", "S1", "S2", "S3", "S4", "S5"}]
    strong_true_primary = [sid for sid in strong_true_all if sid in {"S0", "S2", "S4"}]
    weak_true = [sid for sid, s in signals.items() if s["result_class"] == RESULT_WEAK_TRUE and sid in {"S1", "S3", "S5"}]
    strong_false = [sid for sid, s in signals.items() if s["result_class"] == RESULT_STRONG_FALSE and sid in {"S0"}]
    weak_false = [sid for sid, s in signals.items() if s["result_class"] == RESULT_WEAK_FALSE and sid in {"S1", "S2", "S3", "S4"}]
    unknown = [sid for sid, s in signals.items() if s["result_class"] == RESULT_UNKNOWN and sid in {"S0", "S1", "S2", "S3", "S4", "S5"}]

    if strong_true_primary:
        return {
            "harness_constrained": True,
            "confidence": "high",
            "triggers": strong_true_primary,
        }
    if strong_true_all:
        return {
            "harness_constrained": True,
            "confidence": "medium",
            "triggers": strong_true_all,
        }
    if len(weak_true) >= 2:
        return {
            "harness_constrained": True,
            "confidence": "medium",
            "triggers": weak_true,
        }
    if len(unknown) == len([sid for sid in ("S0", "S1", "S2", "S3", "S4", "S5") if sid in signals]):
        return {
            "harness_constrained": None,
            "confidence": "low",
            "triggers": [],
        }

    confidence = "medium"
    if "S0" in strong_false and "S2" in weak_false:
        confidence = "high"
    return {
        "harness_constrained": False,
        "confidence": confidence,
        "triggers": strong_false + weak_false,
    }


def _format_summary(summary: Dict[str, Any]) -> str:
    constrained = summary.get("harness_constrained")
    constrained_text = "unknown"
    if constrained is True:
        constrained_text = "true"
    elif constrained is False:
        constrained_text = "false"
    triggers = ",".join(summary.get("triggers", []))
    if not triggers:
        triggers = "none"
    return (
        "INSIDE_SANDBOX_DETECT: constrained="
        f"{constrained_text} confidence={summary.get('confidence')} triggers={triggers}"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true", help="emit JSON only")
    parser.add_argument("--include-apply", action="store_true", help="run S4 apply sensor")
    parser.add_argument("--with-logs", action="store_true", help="run S5 log corroboration")
    parser.add_argument("--policywitness-bin", default=DEFAULT_POLICYWITNESS_BIN)
    parser.add_argument("--policywitness-service", default=DEFAULT_POLICYWITNESS_SERVICE)
    parser.add_argument("--mach-control-service", default=DEFAULT_MACH_CONTROL_SERVICE)
    parser.add_argument("--bootstrap-name", action="append", dest="bootstrap_names")
    parser.add_argument("--sbpl-wrapper", default=DEFAULT_SBPL_WRAPPER)
    parser.add_argument("--sbpl-profile", default=DEFAULT_SBPL_PROFILE)
    parser.add_argument("--log-bin", default="/usr/bin/log")
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--no-unfiltered", action="store_true", help="disable unfiltered mach-lookup fallback")
    parser.add_argument("--disable-vendored", action="store_true", help="disable vendored filter constants")
    args = parser.parse_args()

    repo_root = _repo_root()
    world_id = baseline_world_id(repo_root)

    policywitness_bin_exec, policywitness_bin_rel = _resolve_exec_target(repo_root, args.policywitness_bin)
    sbpl_wrapper_exec, sbpl_wrapper_rel = _resolve_exec_target(repo_root, args.sbpl_wrapper)
    sbpl_profile_exec, sbpl_profile_rel = _resolve_exec_target(repo_root, args.sbpl_profile)
    log_bin_exec, log_bin_rel = _resolve_exec_target(repo_root, args.log_bin)

    bootstrap_names = args.bootstrap_names or list(DEFAULT_BOOTSTRAP_NAMES)
    allow_unfiltered = not args.no_unfiltered
    allow_vendored = not args.disable_vendored

    start_ts = dt.datetime.now().astimezone()

    signals: Dict[str, Dict[str, Any]] = {}
    signals["S0"] = _sensor_s0()
    signals["S1"] = _sensor_s1(
        args.policywitness_service,
        args.mach_control_service,
        allow_unfiltered=allow_unfiltered,
        allow_vendored=allow_vendored,
    )
    signals["S2"] = _sensor_s2(bootstrap_names)
    signals["S3"] = _sensor_s3(
        policywitness_bin_exec,
        policywitness_bin_rel,
        args.policywitness_service,
        timeout_s=args.timeout,
    )
    signals["S4"] = _sensor_s4(
        sbpl_wrapper_exec,
        sbpl_wrapper_rel,
        sbpl_profile_exec,
        sbpl_profile_rel,
        timeout_s=args.timeout,
        include_apply=args.include_apply,
    )

    end_ts = dt.datetime.now().astimezone()
    log_predicate = (
        '((processID == 0) AND (senderImagePath CONTAINS "/Sandbox")) '
        'OR (subsystem == "com.apple.sandbox.reporting")'
    )
    signals["S5"] = _sensor_s5(
        log_bin_exec,
        log_predicate,
        start_ts,
        end_ts,
        os.getpid(),
        include_logs=args.with_logs,
    )
    signals["S6"] = _sensor_s6()

    summary = _score_harness(signals)

    payload = {
        "schema_version": 1,
        "tool": "inside",
        "world_id": world_id,
        "pid": os.getpid(),
        "policywitness_bin": policywitness_bin_rel,
        "sbpl_wrapper": sbpl_wrapper_rel,
        "sbpl_profile": sbpl_profile_rel,
        "log_bin": log_bin_rel,
        "signals": {key: signals[key] for key in SENSOR_ORDER if key in signals},
        "summary": summary,
    }

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(_format_summary(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
