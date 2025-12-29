# Trace product decisions (Frida)

This record locks headless invariants for the Frida trace product used by `book/api/frida` and related tooling.

It is intentionally **non-interactive**: every analysis/validation step must be runnable lights‑out with deterministic outputs and stable exit codes.

## 1) Authoritative event time

**Decision**: authoritative event time is **wall clock** sampled with `time.time_ns()` (**Unix epoch**, **nanoseconds**).

- **Sampling point**:
  - runner-stage events: timestamp at emission
  - agent events: timestamp at receipt (Frida `on("message", ...)` callback)
- **Agent-provided timestamps** (if a hook includes its own timestamp fields) are treated as **payload-only**; they are not promoted to authoritative time.

Rationale: the existing compatibility surface already records `t_ns` as epoch-nanoseconds; keeping this as authoritative avoids inventing a second clock domain for legacy runs.

## 2) Required fields on every trace event (trace v1)

Every JSONL line in a trace v1 `events.jsonl` MUST be a single JSON object with:

- `schema_name`: string (constant for this product)
- `schema_version`: integer (currently `1`)
- `run_id`: string (UUID or stable run identifier)
- `seq`: integer (run-scoped, strictly increasing in write order)
- `t_ns`: integer (authoritative time; epoch-nanoseconds)
- `pid`: integer or `null` (pid at capture time if known)
- `source`: string enum (`"runner"` or `"agent"`)
- `kind`: string (source-specific discriminator)

Source-specific payload requirements:

- `source == "runner"`: include `runner` (object) and omit `agent`/`hook_payload`
- `source == "agent"`: include `agent` (object); include `hook_payload` (object) only when the agent message is a `send()`

## 3) Optional and derived fields

Optional envelope fields may exist to improve query/export usability, but must remain **derived** (not required for correctness). Examples:

- `hook_payload_kind`: string copied from `hook_payload.kind` when present
- `runner_stage`: string copied from `runner.stage` for stage events
- `errors`: structured error fields for deterministic failure classification

Derived fields must never delete, rename, or otherwise invalidate the preserved raw hook payload.

## 4) Exporter + query choices (headless-only)

**Exporter (artifact-only)**:
- Export format: Chrome Trace JSON (Perfetto/Chrome trace-viewer compatible) is acceptable.
- Export is validated headlessly via deterministic structural checks (parseable JSON; required sections present; counts/ts ranges reported).
- No “done” criterion requires opening a UI; UI viewing is an optional consumer behavior only.

**Query backend (automation)**:
- SQL backend is DuckDB-first.
- Querying must support deterministic JSON outputs suitable for CI diffs (stable ordering, stable serialization).

These decisions are applied by the v1 envelope and normalization tooling described in `book/api/frida/TRACE_SCHEMA_V1.md` (which in turn must point back to `book/api/frida/TRACE_COMPATIBILITY.md`).

