"""
Normalize MACF wrapper trace logs into JSON with syscall correlation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
from typing import Dict, Iterable, List, Optional

from book.api import path_utils

CORRELATION_WINDOW_NS = 10_000_000  # 10 ms
DERIVED_OPERATION = {
    "mac_vnode_check_open": "vnode_open",
    "mac_vnop_setxattr": "vnode_setxattr",
}
HOOK_TO_SYSCALL = {
    "mac_vnode_check_open": {"open", "open_nocancel", "open_extended", "openat", "openat_nocancel"},
    "mac_vnop_setxattr": {"setxattr", "fsetxattr", "lsetxattr"},
}
ACC_MODE_FLAGS = {0x1: "read", 0x2: "write"}

def sha256_hex(path: pathlib.Path) -> Optional[str]:
    if not path or not path.exists():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()

def _to_int(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value, 0)
    except ValueError:
        return None

def decode_acc_mode(acc_mode: Optional[str]) -> List[str]:
    flags: List[str] = []
    val = _to_int(acc_mode)
    if val is None:
        return flags
    for bit, label in ACC_MODE_FLAGS.items():
        if val & bit:
            flags.append(label)
    return flags

def parse_event_line(line: str) -> Optional[Dict[str, str]]:
    stripped = line.strip()
    if not stripped or not stripped.startswith("EVENT"):
        return None
    fields: Dict[str, str] = {}
    for token in stripped.split()[1:]:
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        fields[key] = value
    return fields

def parse_raw_log(lines: Iterable[str]) -> List[Dict]:
    events: List[Dict] = []
    for line in lines:
        fields = parse_event_line(line)
        if fields is None:
            continue
        kind = fields.get("kind")
        pid = _to_int(fields.get("pid"))
        tid = _to_int(fields.get("tid"))
        ts = _to_int(fields.get("ts"))
        if kind == "hook":
            hook = fields.get("hook")
            args: Dict[str, str] = {}
            if hook == "mac_vnode_check_open":
                args = {"ctx": fields.get("ctx"), "vp": fields.get("vp"), "acc_mode": fields.get("acc_mode")}
            elif hook == "mac_vnop_setxattr":
                args = {"vp": fields.get("vp"), "name_ptr": fields.get("name_ptr"), "buf_ptr": fields.get("buf_ptr"), "len": fields.get("len")}
            events.append({
                "kind": "hook",
                "hook": hook,
                "pid": pid,
                "tid": tid,
                "exec": fields.get("exec"),
                "timestamp_ns": ts,
                "args": args,
                "world": fields.get("world"),
                "run_id": fields.get("run_id"),
            })
        elif kind == "syscall":
            sys_name = fields.get("sys")
            sys_fields: Dict[str, str] = {}
            if sys_name and sys_name.startswith("open"):
                sys_fields = {"path": fields.get("path"), "flags": fields.get("flags")}
            elif sys_name == "setxattr":
                sys_fields = {"path": fields.get("path"), "xattr_name": fields.get("name"), "size": fields.get("size")}
            elif sys_name == "fsetxattr":
                sys_fields = {"fd": fields.get("fd"), "xattr_name": fields.get("name"), "size": fields.get("size")}
            events.append({
                "kind": "syscall",
                "sys": sys_name,
                "pid": pid,
                "tid": tid,
                "exec": fields.get("exec"),
                "timestamp_ns": ts,
                "fields": sys_fields,
            })
    return events

def _match_syscall(hook_event: Dict, sys_events: List[Dict]) -> Optional[Dict]:
    hook_name = hook_event.get("hook")
    allowed = HOOK_TO_SYSCALL.get(hook_name, set())
    hook_ts = hook_event.get("timestamp_ns")
    for sys_ev in reversed(sys_events):
        if sys_ev.get("sys") not in allowed:
            continue
        sys_ts = sys_ev.get("timestamp_ns")
        if hook_ts is not None and sys_ts is not None:
            if sys_ts > hook_ts:
                continue
            if hook_ts - sys_ts > CORRELATION_WINDOW_NS:
                break
        return sys_ev
    return None

def correlate_events(raw_events: List[Dict], runtime_world_id: str, run_id: str) -> List[Dict]:
    sorted_events = sorted(raw_events, key=lambda ev: ev.get("timestamp_ns") or 0)
    sys_by_thread: Dict[tuple, List[Dict]] = {}
    hook_outputs: List[Dict] = []
    for ev in sorted_events:
        key = (ev.get("pid"), ev.get("tid"))
        if ev.get("kind") == "syscall":
            sys_by_thread.setdefault(key, []).append(ev)
            continue
        if ev.get("kind") != "hook":
            continue
        matched_sys = _match_syscall(ev, sys_by_thread.get(key, []))
        hook_name = ev.get("hook")
        derived_op = DERIVED_OPERATION.get(hook_name)
        op_flags: List[str] = []
        args = ev.get("args") or {}
        if hook_name == "mac_vnode_check_open":
            op_flags = decode_acc_mode(args.get("acc_mode"))
        syscall_obj = None
        if matched_sys:
            syscall_obj = {"sys": matched_sys.get("sys")}
            syscall_fields = matched_sys.get("fields") or {}
            syscall_obj.update(syscall_fields)
            syscall_obj["timestamp_ns"] = matched_sys.get("timestamp_ns")
        hook_outputs.append({
            "hook": hook_name,
            "pid": ev.get("pid"),
            "tid": ev.get("tid"),
            "execname": ev.get("exec"),
            "timestamp_ns": ev.get("timestamp_ns"),
            "args": args,
            "derived_operation": derived_op,
            "operation_flags": op_flags,
            "syscall": syscall_obj,
            "world_id": runtime_world_id,
            "run_id": run_id,
        })
    return hook_outputs

def _percentile(values: List[float], pct: float) -> Optional[float]:
    if not values:
        return None
    values_sorted = sorted(values)
    k = (len(values_sorted) - 1) * pct
    f = int(k)
    c = min(f + 1, len(values_sorted) - 1)
    if f == c:
        return values_sorted[f]
    d0 = values_sorted[f] * (c - k)
    d1 = values_sorted[c] * (k - f)
    return d0 + d1


def summarize_events(hook_events: List[Dict], *, runtime_world_id: str, run_id: str, scenario: Optional[str], scenario_description: Optional[str]) -> Dict:
    hook_counts: Dict[str, int] = {}
    syscall_counts: Dict[str, int] = {}
    correlation: Dict[str, Dict[str, Optional[float]]] = {}
    for ev in hook_events:
        hook = ev.get("hook")
        if hook:
            hook_counts[hook] = hook_counts.get(hook, 0) + 1
        syscall = ev.get("syscall") or {}
        sys_name = syscall.get("sys")
        if sys_name:
            syscall_counts[sys_name] = syscall_counts.get(sys_name, 0) + 1
        hook_ts = ev.get("timestamp_ns")
        sys_ts = syscall.get("timestamp_ns")
        if hook_ts is None or sys_ts is None:
            continue
        delta_us = (hook_ts - sys_ts) / 1000.0
        key = f"{hook}/{sys_name}"
        entry = correlation.setdefault(key, {"deltas_us": []})
        entry["deltas_us"].append(delta_us)

    correlation_stats: Dict[str, Dict[str, Optional[float]]] = {}
    for key, data in correlation.items():
        deltas = data.get("deltas_us", [])
        correlation_stats[key] = {
            "count": len(deltas),
            "min_delta_us": min(deltas) if deltas else None,
            "max_delta_us": max(deltas) if deltas else None,
            "p50_delta_us": _percentile(deltas, 0.5),
            "p95_delta_us": _percentile(deltas, 0.95),
        }

    return {
        "runtime_world_id": runtime_world_id,
        "run_id": run_id,
        "scenario": scenario,
        "scenario_description": scenario_description,
        "hook_counts": hook_counts,
        "syscall_counts": syscall_counts,
        "correlation": correlation_stats,
    }


def build_output(*, events: List[Dict], runtime_world_id: str, run_id: str, os_build: Optional[str], kernel_version: Optional[str], provider: str, module: str, hooks: List[str], run_command: Optional[str], target_pid: Optional[int], static_refs: Dict[str, Optional[str]], scenario: Optional[str], scenario_description: Optional[str]) -> Dict:
    hook_events = correlate_events(events, runtime_world_id=runtime_world_id, run_id=run_id)
    summary = summarize_events(
        hook_events,
        runtime_world_id=runtime_world_id,
        run_id=run_id,
        scenario=scenario,
        scenario_description=scenario_description,
    )
    return {
        "runtime_world_id": runtime_world_id,
        "run_id": run_id,
        "scenario": scenario,
        "scenario_description": scenario_description,
        "os_build": os_build,
        "kernel_version": kernel_version,
        "provider": provider,
        "module": module,
        "hooks": hooks,
        "run_command": run_command,
        "target_pid": target_pid,
        "static_reference": static_refs,
        "events": hook_events,
        "summary": summary,
    }

def resolve_default_static_refs(repo_root: pathlib.Path) -> Dict[str, Optional[str]]:
    op_table = repo_root / "book/graph/mappings/op_table/op_table_signatures.json"
    vocab_ops = repo_root / "book/graph/mappings/vocab/ops.json"
    vocab_filters = repo_root / "book/graph/mappings/vocab/filters.json"
    return {
        "op_table_hash": sha256_hex(op_table),
        "vocab_ops_hash": sha256_hex(vocab_ops),
        "vocab_filters_hash": sha256_hex(vocab_filters),
    }

def main() -> int:
    parser = argparse.ArgumentParser(description="Normalize MACF wrapper DTrace logs.")
    parser.add_argument("--raw", required=True, help="Path to raw DTrace log file.")
    parser.add_argument("--out", required=True, help="Output JSON path.")
    parser.add_argument("--run-id", required=True, help="Run identifier.")
    parser.add_argument("--runtime-world-id", required=True, help="Runtime world identifier.")
    parser.add_argument("--scenario", default=None, help="Scenario identifier.")
    parser.add_argument("--scenario-description", default=None, help="Scenario description.")
    parser.add_argument("--os-build", default=None, help="OS build string.")
    parser.add_argument("--kernel-version", default=None, help="Kernel version string.")
    parser.add_argument("--provider", default="fbt", help="DTrace provider used for capture.")
    parser.add_argument("--module", default="mach_kernel", help="Probe module name.")
    parser.add_argument("--hooks", nargs="*", default=[], help="Hooks targeted in this run.")
    parser.add_argument("--run-command", default=None, help="Command executed under tracing.")
    parser.add_argument("--target-pid", type=int, default=None, help="Target pid if attaching with -p.")
    parser.add_argument("--no-static-ref", action="store_true", help="Skip computing static reference hashes.")
    parser.add_argument("--summary-out", default=None, help="Optional summary JSON output path.")
    args = parser.parse_args()

    repo_root = path_utils.find_repo_root()
    raw_path = path_utils.ensure_absolute(repo_root / args.raw)
    out_path = path_utils.ensure_absolute(repo_root / args.out)

    with raw_path.open() as f:
        events = parse_raw_log(f.readlines())

    static_refs = {"op_table_hash": None, "vocab_ops_hash": None, "vocab_filters_hash": None}
    if not args.no_static_ref:
        static_refs = resolve_default_static_refs(repo_root)

    output = build_output(
        events=events,
        runtime_world_id=args.runtime_world_id,
        run_id=args.run_id,
        os_build=args.os_build,
        kernel_version=args.kernel_version,
        provider=args.provider,
        module=args.module,
        hooks=args.hooks,
        run_command=args.run_command,
        target_pid=args.target_pid,
        static_refs=static_refs,
        scenario=args.scenario,
        scenario_description=args.scenario_description,
    )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w") as f:
        json.dump(output, f, indent=2, sort_keys=True)
    if args.summary_out:
        summary_path = path_utils.ensure_absolute(repo_root / args.summary_out)
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        with summary_path.open("w") as f:
            json.dump(output.get("summary", {}), f, indent=2, sort_keys=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
