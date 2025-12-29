"""Headless schema checks for Frida trace products."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from book.api.frida import trace_v1
from book.api import path_utils


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def validate_trace_event_v1(event: Any) -> List[str]:
    errors: List[str] = []
    if not isinstance(event, dict):
        return ["event must be a JSON object"]

    if event.get("schema_name") != trace_v1.TRACE_EVENT_SCHEMA_NAME:
        errors.append("schema_name mismatch")
    if event.get("schema_version") != trace_v1.TRACE_EVENT_SCHEMA_VERSION:
        errors.append("schema_version mismatch")

    run_id = event.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        errors.append("run_id must be a non-empty string")

    seq = event.get("seq")
    if not _is_int(seq) or seq < 0:
        errors.append("seq must be an int >= 0")

    t_ns = event.get("t_ns")
    if not _is_int(t_ns) or t_ns < 0:
        errors.append("t_ns must be an int >= 0")

    pid = event.get("pid")
    if pid is not None and (not _is_int(pid) or pid < 0):
        errors.append("pid must be an int >= 0 or null")

    source = event.get("source")
    if source not in ("runner", "agent"):
        errors.append("source must be 'runner' or 'agent'")

    kind = event.get("kind")
    if not isinstance(kind, str) or not kind:
        errors.append("kind must be a non-empty string")

    if source == "runner":
        runner = event.get("runner")
        if not isinstance(runner, dict):
            errors.append("runner event must include runner object")
        if "agent" in event:
            errors.append("runner event must not include agent")
        if "hook_payload" in event:
            errors.append("runner event must not include hook_payload")
    elif source == "agent":
        agent = event.get("agent")
        if not isinstance(agent, dict):
            errors.append("agent event must include agent object")
        if "runner" in event:
            errors.append("agent event must not include runner")
        hook_payload = event.get("hook_payload", None)
        if kind == "send" and "hook_payload" not in event:
            errors.append("send events must include hook_payload (may be null)")
        if "hook_payload" in event and kind != "send":
            errors.append("hook_payload is only valid for kind == 'send'")

        hook_payload_kind = event.get("hook_payload_kind", None)
        if hook_payload_kind is not None and not isinstance(hook_payload_kind, str):
            errors.append("hook_payload_kind must be a string or null")
        if isinstance(hook_payload, dict) and isinstance(hook_payload.get("kind"), str):
            expected = hook_payload["kind"]
            if hook_payload_kind is not None and hook_payload_kind != expected:
                errors.append("hook_payload_kind must match hook_payload.kind when present")

    return errors


def validate_events_jsonl(events_path: Path) -> Dict[str, Any]:
    errors: List[Dict[str, Any]] = []
    count = 0
    for idx, line in enumerate(events_path.read_text().splitlines(), start=1):
        if not line.strip():
            continue
        count += 1
        try:
            event = json.loads(line)
        except Exception as exc:
            errors.append({"line": idx, "error": f"invalid json: {type(exc).__name__}: {exc}"})
            continue
        ev_errors = validate_trace_event_v1(event)
        if ev_errors:
            errors.append({"line": idx, "error": "schema violations", "violations": ev_errors})
    return {"event_count": count, "ok": not errors, "errors": errors}


def _repo_rel(path: Path, repo_root: Path) -> str:
    return path_utils.to_repo_relative(path, repo_root)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--examples",
        action="store_true",
        help="Validate the checked-in trace v1 examples JSON",
    )
    ap.add_argument(
        "--events-jsonl",
        help="Validate a specific events.jsonl path against the trace v1 envelope",
    )
    ap.add_argument(
        "--run-dir",
        help="Validate <run_dir>/events.jsonl against the trace v1 envelope",
    )
    args = ap.parse_args(argv)

    repo_root = path_utils.find_repo_root()
    reports: List[Dict[str, Any]] = []

    if args.examples:
        examples_path = repo_root / "book/api/frida/schemas/trace_event_v1.examples.json"
        events = json.loads(examples_path.read_text())
        if not isinstance(events, list):
            raise SystemExit("examples file must be a JSON array")
        errors: List[Dict[str, Any]] = []
        for idx, ev in enumerate(events):
            ev_errors = validate_trace_event_v1(ev)
            if ev_errors:
                errors.append({"index": idx, "error": "schema violations", "violations": ev_errors})
        reports.append(
            {
                "kind": "examples",
                "path": _repo_rel(examples_path, repo_root),
                "event_count": len(events),
                "ok": not errors,
                "errors": errors,
            }
        )

    events_path: Path | None = None
    if args.events_jsonl:
        events_path = path_utils.ensure_absolute(args.events_jsonl, repo_root)
    elif args.run_dir:
        run_dir = path_utils.ensure_absolute(args.run_dir, repo_root)
        events_path = run_dir / "events.jsonl"

    if events_path is not None:
        reports.append(
            {
                "kind": "events_jsonl",
                "path": _repo_rel(events_path, repo_root),
                **validate_events_jsonl(events_path),
            }
        )

    ok = all(r.get("ok") for r in reports) if reports else False
    out = {"ok": ok, "reports": reports}
    sys.stdout.write(json.dumps(out, indent=2, sort_keys=True) + "\n")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
