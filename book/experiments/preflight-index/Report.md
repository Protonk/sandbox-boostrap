# preflight-index — Report

## Purpose

Create a small “preflight index” experiment that scans in-repo profile inputs with `book/tools/preflight` and emits a manifest plus summary counts. The goal is operational: give agents an **artifact-driven** rule of thumb for profile selection (“prefer profiles with `classification == "no_known_apply_gate_signature"` unless explicitly studying apply gates”) without re-learning EPERMx2 narratives.

## Baseline & scope

- World: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
- Inputs scanned (deterministic inventory):
  - `book/profiles/**/*.sb`
  - `book/experiments/**/*.sb` (excluding `out/`)
  - `book/examples/**/*.sb`
  - `book/**/*.sb.bin`
- Tooling:
  - Preflight classifier: `book/tools/preflight/preflight.py` (static; does not compile or apply profiles).
- Non-goals:
  - Proving that “no signature” implies apply success (it does not).
  - Explaining why apply gating exists (see `book/experiments/gate-witnesses/` and `troubles/EPERMx2.md`).

## Status

- Status: **ok (operational)**.
- The checked-in manifest is intended to be kept in sync by a test guardrail and regenerated when inputs change.

## Artifacts

- Manifest: `book/tools/preflight/index/preflight_enterability_manifest.json`
- Summary: `book/tools/preflight/index/summary.json`
- Legacy snapshots: `out/preflight_enterability_manifest.json`, `out/summary.json` (provenance only)

## Current cut (checked-in)

From `book/tools/preflight/index/summary.json`:

- Total inputs scanned: 622
- `likely_apply_gated_for_harness_identity`: 27
- `no_known_apply_gate_signature`: 595

## Lessons (operational invariants for agents)

- Treat `classification == "likely_apply_gated_for_harness_identity"` as “do not attempt apply from a generic harness identity” unless the task is explicitly about apply gating.
- Treat `classification == "no_known_apply_gate_signature"` as “no known apply-gate signature” (not a success guarantee).

## Notes

See `Notes.md` for the command log and regeneration pointers.
