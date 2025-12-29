# Configure Contract v1

This document defines the v1 contract for optional Frida hook configuration via `rpc.exports.configure`.

This contract is part of the headless trace-product pipeline; runs must remain non-interactive and deterministic, and failures must be machine-detectable.

## Contract

### Function name

- `configure`

### Invocation timing (runner/capture responsibility)

- Runner/capture calls `configure()` **immediately after** `script.load()` succeeds.
- Runner/capture calls `configure()` **before** recording any post-load “run started” stage (for example: before `resume`, `attach-loop`, or “hold open” stages).
- Hook-side responsibility: hooks that need configuration to affect interception behavior must **defer installing interceptors** until after configuration has been received.

### Input type

- Input is a JSON object (map/dict).
- Input is never `null`.
- Empty object `{}` is allowed.

### Return type

- Return is a JSON object (map/dict); empty object `{}` is allowed.
- The return value is snapshotted into the run record.

### Error semantics

- Any thrown/raised error is treated as a configure failure.
- Configure failure must produce:
  - a first-class `configure-error` runner event in `events.jsonl`
  - deterministic non-zero exit in the generic runner
  - deterministic error surface in capture/EJ-integrated paths

### Idempotency expectation

- Runner/capture calls `configure()` at most once per run (enforced).
- Hooks must treat repeated calls as an error, even if the orchestrator never calls twice.

### Recording requirements

For every run, regardless of whether the hook exposes `configure`, `meta.json` must record:
- the config snapshot used (`script.config`)
- the config validation result (`script.config_validation`)
- the configure status/result/error (`script.configure`)

