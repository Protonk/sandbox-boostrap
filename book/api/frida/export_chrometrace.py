"""Chrome Trace JSON exporter for Frida trace v1 runs (headless)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from book.api import path_utils
from book.api.frida.schema_validate import validate_trace_event_v1


class ExportError(Exception):
    pass


def _read_json(path: Path) -> Dict[str, Any]:
    try:
        data = json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise ExportError(f"missing file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ExportError(f"invalid JSON: {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ExportError(f"expected JSON object: {path}")
    return data


def _read_events(events_path: Path) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    for idx, line in enumerate(events_path.read_text().splitlines(), start=1):
        if not line.strip():
            continue
        try:
            ev = json.loads(line)
        except Exception as exc:
            raise ExportError(f"invalid json line {idx}: {type(exc).__name__}: {exc}") from exc
        if not isinstance(ev, dict):
            raise ExportError(f"event line {idx} is not an object")
        violations = validate_trace_event_v1(ev)
        if violations:
            raise ExportError(f"event line {idx} violates trace v1 schema: {violations}")
        events.append(ev)
    return events


def _to_us(t_ns: int, origin_ns: int) -> int:
    return max(0, (t_ns - origin_ns) // 1000)


def _tid_for_event(ev: Dict[str, Any]) -> int:
    hook_payload = ev.get("hook_payload")
    if isinstance(hook_payload, dict):
        tid = hook_payload.get("tid")
        if isinstance(tid, int) and tid >= 0:
            return tid
    return 0


def _pid_for_event(ev: Dict[str, Any]) -> int:
    pid = ev.get("pid")
    if isinstance(pid, int) and pid >= 0:
        return pid
    return 0


def _chrometrace_event(**fields: Any) -> Dict[str, Any]:
    # Keep key ordering deterministic via json.dumps(sort_keys=True) at the end.
    return dict(fields)


def export_run_dir(run_dir: Path, *, out_path: Optional[Path] = None) -> Dict[str, Any]:
    repo_root = path_utils.find_repo_root()
    run_dir_abs = path_utils.ensure_absolute(run_dir, repo_root)
    meta_path = run_dir_abs / "meta.json"
    events_path = run_dir_abs / "events.jsonl"

    meta = _read_json(meta_path)
    events = _read_events(events_path)
    if not events:
        raise ExportError("no events to export")

    t0_ns = min(int(ev["t_ns"]) for ev in events)
    t1_ns = max(int(ev["t_ns"]) for ev in events)

    run_id = meta.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        raise ExportError("meta.json missing run_id")

    trace_events: List[Dict[str, Any]] = []

    # Runner stage spans: stage -> next stage (or end of trace).
    stage_events: List[Tuple[str, Dict[str, Any]]] = []
    for ev in events:
        if ev.get("source") != "runner" or ev.get("kind") != "stage":
            continue
        runner = ev.get("runner")
        stage = runner.get("stage") if isinstance(runner, dict) else None
        if isinstance(stage, str) and stage:
            stage_events.append((stage, ev))

    for i, (stage, ev) in enumerate(stage_events):
        start_ns = int(ev["t_ns"])
        end_ns = int(stage_events[i + 1][1]["t_ns"]) if i + 1 < len(stage_events) else t1_ns
        dur_ns = max(0, end_ns - start_ns)
        pid = _pid_for_event(ev)
        trace_events.append(
            _chrometrace_event(
                name=f"runner:stage:{stage}",
                cat="runner",
                ph="X",
                ts=_to_us(start_ns, t0_ns),
                dur=(dur_ns // 1000),
                pid=pid,
                tid=0,
                args={
                    "run_id": run_id,
                    "stage": stage,
                    "seq": ev.get("seq"),
                },
            )
        )

    # Agent events (instants).
    for ev in events:
        if ev.get("source") != "agent":
            continue
        ts = _to_us(int(ev["t_ns"]), t0_ns)
        pid = _pid_for_event(ev)
        tid = _tid_for_event(ev)
        kind = str(ev.get("kind"))
        hook_kind = ev.get("hook_payload_kind") if isinstance(ev.get("hook_payload_kind"), str) else None
        name = f"hook:{hook_kind}" if (kind == "send" and hook_kind) else f"agent:{kind}"
        trace_events.append(
            _chrometrace_event(
                name=name,
                cat="agent",
                ph="i",
                s="t",
                ts=ts,
                pid=pid,
                tid=tid,
                args={
                    "run_id": run_id,
                    "seq": ev.get("seq"),
                    "hook_payload_kind": hook_kind,
                    "hook_payload": ev.get("hook_payload"),
                    "agent": ev.get("agent"),
                },
            )
        )

    out = {
        "traceEvents": trace_events,
        "displayTimeUnit": "us",
        "frida_run": {
            "run_id": run_id,
            "world_id": meta.get("world_id"),
            "trace_event_schema": meta.get("trace_event_schema"),
            "script": meta.get("script"),
            "mode": meta.get("mode"),
            "target": meta.get("target"),
        },
        "origin": {"t0_ns": t0_ns, "t1_ns": t1_ns},
    }

    out_path_abs = path_utils.ensure_absolute(out_path or (run_dir_abs / "trace.chrometrace.json"), repo_root)
    out_text = json.dumps(out, indent=2, sort_keys=True) + "\n"
    out_path_abs.write_text(out_text)

    # Deterministic export report.
    report_path = run_dir_abs / "trace.chrometrace.report.json"
    runner_span_count = sum(1 for e in trace_events if e.get("ph") == "X" and str(e.get("cat")) == "runner")
    agent_event_count = sum(1 for e in trace_events if str(e.get("cat")) == "agent")
    report = {
        "ok": True,
        "run_dir": path_utils.to_repo_relative(run_dir_abs, repo_root),
        "run_id": run_id,
        "export": {
            "trace_path": path_utils.to_repo_relative(out_path_abs, repo_root),
            "report_path": path_utils.to_repo_relative(report_path, repo_root),
        },
        "counts": {
            "events_in": len(events),
            "runner_stage_spans": runner_span_count,
            "agent_events": agent_event_count,
        },
        "time": {"t0_ns": t0_ns, "t1_ns": t1_ns},
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def validate_chrometrace(trace_path: Path) -> Dict[str, Any]:
    repo_root = path_utils.find_repo_root()
    trace_path_abs = path_utils.ensure_absolute(trace_path, repo_root)
    data = _read_json(trace_path_abs)
    trace_events = data.get("traceEvents")
    if not isinstance(trace_events, list):
        raise ExportError("traceEvents must be a list")

    has_runner_span = any(isinstance(ev, dict) and ev.get("ph") == "X" and str(ev.get("name", "")).startswith("runner:stage:") for ev in trace_events)
    has_hook_event = any(isinstance(ev, dict) and ev.get("ph") == "i" and str(ev.get("name", "")).startswith("hook:") for ev in trace_events)
    frida_run = data.get("frida_run")
    has_run_id = isinstance(frida_run, dict) and isinstance(frida_run.get("run_id"), str) and frida_run.get("run_id")

    ok = bool(has_runner_span and has_hook_event and has_run_id)
    return {
        "ok": ok,
        "trace_path": path_utils.to_repo_relative(trace_path_abs, repo_root),
        "checks": {
            "has_runner_stage_span": bool(has_runner_span),
            "has_hook_event": bool(has_hook_event),
            "has_run_id": bool(has_run_id),
        },
    }

