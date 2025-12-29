"""Trace v1 schema constants and shared helpers."""

from __future__ import annotations

from typing import Any, Dict


TRACE_EVENT_SCHEMA_NAME = "book.api.frida.trace_event"
TRACE_EVENT_SCHEMA_VERSION = 1
TRACE_EVENT_SCHEMA_PATH = "book/api/frida/schemas/trace_event_v1.schema.json"


def trace_event_schema_stamp() -> Dict[str, Any]:
    return {
        "schema_name": TRACE_EVENT_SCHEMA_NAME,
        "schema_version": TRACE_EVENT_SCHEMA_VERSION,
        "schema_path": TRACE_EVENT_SCHEMA_PATH,
        "events_format": "jsonl",
    }

