"""Normalization for Frida run directories (legacy -> trace v1).

This tool is intentionally headless and deterministic:
- stable JSON serialization (sort_keys + compact separators)
- stable sequence numbering (0..N-1 in file order)
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from book.api import path_utils
from book.api.frida.trace_v1 import TRACE_EVENT_SCHEMA_NAME, TRACE_EVENT_SCHEMA_VERSION, trace_event_schema_stamp
from book.api.frida.trace_writer import dumps_jsonl


class NormalizeError(Exception):
    pass


def _sha256_bytes(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


def _read_json(path: Path) -> Dict[str, Any]:
    try:
        data = json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise NormalizeError(f"missing file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise NormalizeError(f"invalid JSON: {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise NormalizeError(f"expected JSON object: {path}")
    return data


def _detect_run_id(meta: Dict[str, Any], run_dir: Path) -> str:
    run_id = meta.get("run_id")
    if isinstance(run_id, str) and run_id:
        return run_id
    attach = meta.get("attach")
    if isinstance(attach, dict):
        rid = attach.get("run_id")
        if isinstance(rid, str) and rid:
            return rid
    # Fall back to directory name for legacy fixtures.
    return run_dir.name


def _is_trace_v1_event(obj: Any) -> bool:
    return (
        isinstance(obj, dict)
        and obj.get("schema_name") == TRACE_EVENT_SCHEMA_NAME
        and obj.get("schema_version") == TRACE_EVENT_SCHEMA_VERSION
    )


def _normalize_agent_fields(event: Dict[str, Any]) -> None:
    if event.get("source") != "agent":
        return
    kind = event.get("kind")
    if kind != "send":
        return
    hook_payload = event.get("hook_payload")
    if isinstance(hook_payload, dict):
        k = hook_payload.get("kind")
        if isinstance(k, str):
            event["hook_payload_kind"] = k
    else:
        event.setdefault("hook_payload_kind", None)


def normalize_events(
    *,
    meta: Dict[str, Any],
    run_dir: Path,
    raw_lines: List[str],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Return (normalized_events, warnings).

    Warnings are machine-readable records that do not affect determinism.
    """
    run_id = _detect_run_id(meta, run_dir)
    warnings: List[Dict[str, Any]] = []
    out: List[Dict[str, Any]] = []

    for idx, line in enumerate(raw_lines):
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except Exception as exc:
            raise NormalizeError(f"invalid json line {idx + 1}: {type(exc).__name__}: {exc}") from exc

        if _is_trace_v1_event(rec):
            event = dict(rec)
            event["run_id"] = run_id
            event["seq"] = len(out)
            _normalize_agent_fields(event)
            out.append(event)
            continue

        if not isinstance(rec, dict):
            raise NormalizeError(f"legacy record must be a JSON object (line {idx + 1})")

        t_ns = rec.get("t_ns")
        if not isinstance(t_ns, int):
            raise NormalizeError(f"legacy record missing int t_ns (line {idx + 1})")
        pid = rec.get("pid")
        if pid is not None and not isinstance(pid, int):
            raise NormalizeError(f"legacy record pid must be int or null (line {idx + 1})")

        msg = rec.get("msg")
        if not isinstance(msg, dict):
            raise NormalizeError(f"legacy record missing msg object (line {idx + 1})")

        msg_type = msg.get("type")
        if not isinstance(msg_type, str) or not msg_type:
            raise NormalizeError(f"legacy record msg.type must be a string (line {idx + 1})")

        if msg_type == "runner":
            payload = msg.get("payload")
            if not isinstance(payload, dict):
                raise NormalizeError(f"runner msg missing payload object (line {idx + 1})")
            kind = payload.get("kind")
            kind_str = str(kind) if kind is not None else "runner"
            out.append(
                {
                    "schema_name": TRACE_EVENT_SCHEMA_NAME,
                    "schema_version": TRACE_EVENT_SCHEMA_VERSION,
                    "run_id": run_id,
                    "seq": len(out),
                    "t_ns": t_ns,
                    "pid": pid,
                    "source": "runner",
                    "kind": kind_str,
                    "runner": payload,
                }
            )
            continue

        # Frida agent message (send/error/...)
        kind_str = msg_type
        event: Dict[str, Any] = {
            "schema_name": TRACE_EVENT_SCHEMA_NAME,
            "schema_version": TRACE_EVENT_SCHEMA_VERSION,
            "run_id": run_id,
            "seq": len(out),
            "t_ns": t_ns,
            "pid": pid,
            "source": "agent",
            "kind": kind_str,
            "agent": msg,
        }
        if kind_str == "send":
            hook_payload = msg.get("payload")
            event["hook_payload"] = hook_payload
            if isinstance(hook_payload, dict):
                k = hook_payload.get("kind")
                if isinstance(k, str):
                    event["hook_payload_kind"] = k
                else:
                    event["hook_payload_kind"] = None
            else:
                event["hook_payload_kind"] = None
        out.append(event)

    return out, warnings


def normalize_run_dir(run_dir: Path) -> Dict[str, Any]:
    repo_root = path_utils.find_repo_root()
    run_dir_abs = path_utils.ensure_absolute(run_dir, repo_root)

    meta_path = run_dir_abs / "meta.json"
    events_path = run_dir_abs / "events.jsonl"

    meta = _read_json(meta_path)
    run_id = _detect_run_id(meta, run_dir_abs)

    raw = events_path.read_bytes()
    raw_sha = _sha256_bytes(raw)
    raw_lines = raw.decode("utf-8").splitlines()

    normalized, warnings = normalize_events(meta=meta, run_dir=run_dir_abs, raw_lines=raw_lines)

    # Ensure meta carries the schema stamp once normalized.
    meta_changed = False
    if meta.get("trace_event_schema") != trace_event_schema_stamp():
        meta["trace_event_schema"] = trace_event_schema_stamp()
        meta_changed = True
    if meta.get("run_id") != run_id:
        meta["run_id"] = run_id
        meta_changed = True

    out_text = "".join(dumps_jsonl(ev) for ev in normalized).encode("utf-8")
    out_sha = _sha256_bytes(out_text)

    tmp_path = events_path.with_suffix(".jsonl.tmp")
    tmp_path.write_bytes(out_text)
    tmp_path.replace(events_path)

    if meta_changed:
        meta_path.write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n")

    return {
        "ok": True,
        "run_dir": path_utils.to_repo_relative(run_dir_abs, repo_root),
        "run_id": run_id,
        "events": {
            "path": path_utils.to_repo_relative(events_path, repo_root),
            "event_count": len(normalized),
            "sha256_before": raw_sha,
            "sha256_after": out_sha,
        },
        "meta": {
            "path": path_utils.to_repo_relative(meta_path, repo_root),
            "updated": meta_changed,
        },
        "warnings": warnings,
    }

