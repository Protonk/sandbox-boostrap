# Trace schema v1 (Frida)

This document defines **trace v1**, the versioned JSONL event envelope for Frida runs.

Compatibility contract and invariants:
- Compatibility inputs are frozen in `book/api/frida/TRACE_COMPATIBILITY.md`.
- Headless invariants (time/required fields/query/export choices) are frozen in `book/api/frida/TRACE_PRODUCT_DECISIONS.md`.

## Overview

Trace v1 makes **every line** in `events.jsonl` a single JSON object with:

- a schema name/version stamp
- a run-scoped sequence number (`seq`)
- an authoritative timestamp (`t_ns`, epoch-nanoseconds; see decisions)
- a source discriminator (`source`: `"runner"` or `"agent"`)
- source-specific payload fields (`runner` or `agent`)
- a dedicated `hook_payload` field that preserves hook `send()` payload objects

## Required vs optional fields

Required fields on every event (v1):
- `schema_name` (string; constant)
- `schema_version` (int; constant `1`)
- `run_id` (string)
- `seq` (int; strictly increasing in write order)
- `t_ns` (int; epoch-nanoseconds)
- `pid` (int or null)
- `source` (`"runner"` or `"agent"`)
- `kind` (string; source-specific discriminator)

Required payload by `source`:
- `source == "runner"`: `runner` (object)
- `source == "agent"`: `agent` (object); `hook_payload` is present when `kind == "send"`

Optional fields (derived / convenience):
- `hook_payload_kind` (string or null): copied from `hook_payload.kind` when present

## Sequence semantics

`seq` is run-scoped and monotonically increasing in file order. It is authoritative for stable ordering when timestamps collide.

## Examples (full JSON)

Runner-stage event:
```json
{
  "schema_name": "book.api.frida.trace_event",
  "schema_version": 1,
  "run_id": "00000000-0000-0000-0000-000000000000",
  "seq": 0,
  "t_ns": 0,
  "pid": null,
  "source": "runner",
  "kind": "stage",
  "runner": {
    "kind": "stage",
    "stage": "device"
  }
}
```

Agent `send()` event (hook payload preserved verbatim under `hook_payload`):
```json
{
  "schema_name": "book.api.frida.trace_event",
  "schema_version": 1,
  "run_id": "00000000-0000-0000-0000-000000000000",
  "seq": 1,
  "t_ns": 1,
  "pid": 123,
  "source": "agent",
  "kind": "send",
  "agent": {
    "type": "send",
    "payload": {
      "kind": "smoke",
      "pid": 123
    }
  },
  "hook_payload": {
    "kind": "smoke",
    "pid": 123
  },
  "hook_payload_kind": "smoke"
}
```

## Machine schema

- Schema file: `book/api/frida/schemas/trace_event_v1.schema.json`
- Example events (for headless validation): `book/api/frida/schemas/trace_event_v1.examples.json`

