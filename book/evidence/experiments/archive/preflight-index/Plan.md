# preflight-index — Plan

> Archived experiment scaffold. Canonical builder: `book/tools/preflight/build_index.py`.

## Purpose

Produce a checked-in, artifact-shaped **enterability manifest** for in-repo profile inputs by running the static preflight classifier across:

- `book/profiles/**/*.sb`
- `book/evidence/experiments/**/*.sb` (excluding `out/`)
- `book/examples/**/*.sb`
- `book/**/*.sb.bin`

This is an operational guardrail for the fixed world baseline (`world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`): it helps agents choose profiles that are not known to be apply-gated for the harness identity unless they are explicitly investigating apply gates.

## Deliverables

- `book/tools/preflight/index/preflight_enterability_manifest.json` — per-input preflight records + minimal file metadata.
- `book/tools/preflight/index/summary.json` — counts and convenience groupings.
- A guardrail test under `book/tests/` that ensures:
  - the manifest covers the current input inventory, and
  - checked-in classifications match current preflight behavior.

## Execution steps

1. Use `book/tools/preflight/build_index.py` to enumerate inputs deterministically and run `book/tools/preflight`.
2. Generate `book/tools/preflight/index/*.json` artifacts and check them in.
3. Add a guardrail test to prevent drift.
4. Add a minimal pointer from preflight docs to the index artifacts.
