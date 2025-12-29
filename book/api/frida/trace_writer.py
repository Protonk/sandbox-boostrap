"""Trace v1 event writer (JSONL).

This module centralizes envelope construction so runner-stage and agent
message events share the same schema and sequencing.
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, Optional, TextIO

from book.api.frida.trace_v1 import TRACE_EVENT_SCHEMA_NAME, TRACE_EVENT_SCHEMA_VERSION


def now_ns() -> int:
    # Authoritative time source is fixed in TRACE_PRODUCT_DECISIONS.md.
    return time.time_ns()


def dumps_jsonl(obj: Dict[str, Any]) -> str:
    # Canonical JSONL serialization: stable key ordering and separators.
    return json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n"


class TraceWriterV1:
    def __init__(self, fp: TextIO, *, run_id: str, pid: Optional[int]) -> None:
        self._fp = fp
        self._run_id = run_id
        self._pid: Optional[int] = pid
        self._seq = 0

    def set_pid(self, pid: Optional[int]) -> None:
        self._pid = pid

    def _emit(self, event: Dict[str, Any]) -> None:
        self._fp.write(dumps_jsonl(event))
        self._fp.flush()
        self._seq += 1

    def emit_runner(self, payload: Dict[str, Any]) -> None:
        kind = payload.get("kind")
        kind_str = str(kind) if kind is not None else "runner"
        self._emit(
            {
                "schema_name": TRACE_EVENT_SCHEMA_NAME,
                "schema_version": TRACE_EVENT_SCHEMA_VERSION,
                "run_id": self._run_id,
                "seq": self._seq,
                "t_ns": now_ns(),
                "pid": self._pid,
                "source": "runner",
                "kind": kind_str,
                "runner": payload,
            }
        )

    def emit_agent_message(self, msg: Dict[str, Any]) -> None:
        msg_type = msg.get("type")
        kind_str = str(msg_type) if msg_type is not None else "agent"

        hook_payload = None
        hook_payload_kind = None
        if kind_str == "send":
            hook_payload = msg.get("payload")
            if isinstance(hook_payload, dict):
                k = hook_payload.get("kind")
                if isinstance(k, str):
                    hook_payload_kind = k

        event: Dict[str, Any] = {
            "schema_name": TRACE_EVENT_SCHEMA_NAME,
            "schema_version": TRACE_EVENT_SCHEMA_VERSION,
            "run_id": self._run_id,
            "seq": self._seq,
            "t_ns": now_ns(),
            "pid": self._pid,
            "source": "agent",
            "kind": kind_str,
            "agent": msg,
        }
        if kind_str == "send":
            event["hook_payload"] = hook_payload
            event["hook_payload_kind"] = hook_payload_kind
        self._emit(event)
