#!/usr/bin/env python3
"""
Codex harness sandbox detection mini-runner.

Runs a best-effort signal set and writes JSON artifacts under out/codex-sandbox/.
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import json
import os
import re
import uuid
from pathlib import Path
from typing import Any, Dict, Optional

from book.api import exec_record, path_utils
from book.api.profile.identity import baseline_world_id
from book.api.runtime.contracts import schema as runtime_schema


SERVICE_DEFAULT = "com.yourteam.policy-witness.ProbeService_minimal"
BOOTSTRAP_DEFAULT = "com.apple.cfprefsd.agent"
SANDBOX_HEADER_CANDIDATES = [
    Path("/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sandbox.h"),
    Path(
        "/Applications/Xcode.app/Contents/Developer/Platforms/"
        "MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/include/sandbox.h"
    ),
]


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
    # Varargs; do not set argtypes.
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
        "sandboxed": (rc == 1) if op is None else None,
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


def _pick_mach_lookup_filter(constants: Dict[str, int]) -> Optional[int]:
    for name in ("SANDBOX_FILTER_XPC_SERVICE_NAME", "SANDBOX_FILTER_GLOBAL_NAME"):
        value = constants.get(name)
        if isinstance(value, int):
            return value
    return None


def _run_policy_witness_sentinel() -> Dict[str, Any]:
    cmd = [
        "book/tools/witness/PolicyWitness.app/Contents/MacOS/policy-witness",
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
    return exec_record.run_command(cmd, timeout_s=25.0, repo_root=_repo_root())


def _run_sbpl_apply() -> Dict[str, Any]:
    cmd = [
        "book/tools/sbpl/wrapper/wrapper",
        "--preflight",
        "enforce",
        "--sbpl",
        "book/experiments/runtime-final-final/suites/sbpl-graph-runtime/profiles/allow_all.sb",
        "--",
        "/usr/bin/true",
    ]
    return exec_record.run_command(cmd, timeout_s=25.0, repo_root=_repo_root())


def _run_log_corroboration(predicate: str, last_s: int, pid: int) -> Dict[str, Any]:
    cmd = [
        "/usr/bin/log",
        "show",
        "--style",
        "syslog",
        "--last",
        f"{last_s}s",
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
    record["deny_lines"] = deny_lines
    record["deny_lines_pid"] = pid_lines
    record["observed_deny"] = bool(deny_lines)
    record["observed_deny_pid"] = bool(pid_lines)
    record["observed_pid"] = pid
    return record


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
        "service_bundle_id": (data.get("details") or {}).get("service_bundle_id")
        if isinstance(data.get("details"), dict)
        else None,
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


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", default="normal", choices=["normal", "elevated"])
    parser.add_argument("--service-name", default=SERVICE_DEFAULT)
    parser.add_argument("--bootstrap-name", default=BOOTSTRAP_DEFAULT)
    args = parser.parse_args()

    repo_root = _repo_root()
    world_id = baseline_world_id(repo_root)

    run_id = str(uuid.uuid4())
    out_root = repo_root / "book" / "experiments" / "codex-sandbox" / "out" / "codex-sandbox"
    run_dir = out_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    signals: Dict[str, Dict[str, Any]] = {}
    constants = _load_sandbox_constants()

    s0 = _sandbox_check(None, filter_type=0)
    s0["signal_id"] = "S0"
    s0["note"] = "sandbox_check(getpid(), NULL, SANDBOX_FILTER_NONE)"
    signals["S0"] = s0
    _write_json(run_dir / "s0_self_sandbox.json", s0)

    filter_type = _pick_mach_lookup_filter(constants)
    if filter_type is None:
        s1 = _sandbox_check("mach-lookup", filter_type=0, target=None)
        s1["signal_id"] = "S1"
        s1["note"] = "sandbox_check(mach-lookup) unfiltered fallback; constants missing"
        s1["filter_type"] = None
        s1["target"] = None
        s1["constants_source"] = constants.get("source_path")
        s1["filter_fallback"] = "none"
    else:
        s1 = _sandbox_check("mach-lookup", filter_type=filter_type, target=args.service_name)
        s1["signal_id"] = "S1"
        s1["note"] = "sandbox_check(mach-lookup)"
        s1["constants_source"] = constants.get("source_path")
    signals["S1"] = s1
    _write_json(run_dir / "s1_mach_lookup.json", s1)

    s2 = _bootstrap_lookup(args.bootstrap_name)
    s2["signal_id"] = "S2"
    s2["note"] = "bootstrap_look_up"
    signals["S2"] = s2
    _write_json(run_dir / "s2_bootstrap_lookup.json", s2)

    s3_raw = _run_policy_witness_sentinel()
    s3 = dict(s3_raw)
    s3.update(_summarize_xpc(s3_raw.get("stdout", "")))
    s3["signal_id"] = "S3"
    signals["S3"] = s3
    _write_json(run_dir / "s3_sentinel_xpc.json", s3)

    s4_raw = _run_sbpl_apply()
    s4 = dict(s4_raw)
    s4.update(_summarize_sbpl(s4_raw.get("stderr", "")))
    s4["signal_id"] = "S4"
    signals["S4"] = s4
    _write_json(run_dir / "s4_sbpl_apply.json", s4)

    predicate = (
        '((processID == 0) AND (senderImagePath CONTAINS "/Sandbox")) '
        'OR (subsystem == "com.apple.sandbox.reporting")'
    )
    s5_raw = _run_log_corroboration(predicate, last_s=10, pid=os.getpid())
    s5 = dict(s5_raw)
    s5["signal_id"] = "S5"
    s5["predicate"] = predicate
    signals["S5"] = s5
    _write_json(run_dir / "s5_log_corroboration.json", s5)

    manifest = {
        "schema_version": 1,
        "world_id": world_id,
        "run_id": run_id,
        "mode": args.mode,
        "service_name": args.service_name,
        "bootstrap_name": args.bootstrap_name,
        "signals": {
            key: path_utils.to_repo_relative(run_dir / f"{key.lower()}_{name}.json", repo_root)
            for key, name in [
                ("S0", "self_sandbox"),
                ("S1", "mach_lookup"),
                ("S2", "bootstrap_lookup"),
                ("S3", "sentinel_xpc"),
                ("S4", "sbpl_apply"),
                ("S5", "log_corroboration"),
            ]
        },
    }
    _write_json(run_dir / "manifest.json", manifest)

    print(path_utils.to_repo_relative(run_dir / "manifest.json", repo_root))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
