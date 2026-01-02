# deny-delay-detail (Report)

Baseline: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5` (Sonoma 14.4.1 / 23E224, arm64).

## Purpose

Turn the intermittent “missing deny evidence” problem into a repeatable method and a reliability matrix, so future experiments do not re-learn observer pitfalls from scratch.

## Baseline & scope

- Host-scoped to the baseline above.
- Focused on PolicyWitness observer evidence and mapped operation/filter outputs.
- Uses bedrock vocab surfaces (see `book/evidence/graph/concepts/BEDROCK_SURFACES.json`):
  - `book/evidence/graph/mappings/vocab/ops.json`
  - `book/evidence/graph/mappings/vocab/filters.json`
  - `book/evidence/graph/mappings/vocab/ops_coverage.json`

## Deliverables / expected outcomes

- `Plan.md`, `Report.md`, `Notes.md` (this experiment scaffold).
- Reliability matrix artifacts (machine + human readable).
- A short playbook that explains the decision ladder used to resolve missing deny evidence.
- A tri-run comparison sample that exercises `book.api.witness` baseline comparisons for a Downloads-shaped probe.

## Plan & execution log

- Reliability matrix run via `run_reliability.py` (manual/external: 2 iterations each; capture: 1 iteration).
  - External observer mode is the most stable for the Downloads ladder in this run set (mapped evidence tier).
    - Stable rows: 18; stable mapped rows: 14 (stage=operation, lane=scenario).
  - Manual observer mode is less stable (mapped evidence tier when denies are observed).
    - Stable rows: 9; stable mapped rows: 5 (stage=operation, lane=scenario).
  - Capture observer mode failed to produce usable evidence (hypothesis tier).
    - Host log capture reports `missing child_pid for sandbox log capture` (stage=operation, lane=scenario).
- Investigated XPC openSession failure:
  - Direct `policy-witness xpc run` calls for `fs_op` (tmp and downloads) succeed; the earlier openSession failure is not reproducible in isolation.
  - Evidence remains in `downloads_direct_3ba22aa95682` (stage=bootstrap, lane=scenario, hypothesis).
- Tri-run comparisons via `run_compare.py`:
  - Path-class Downloads (`downloads_direct_a11650ccf1be`): entitlements run reaches operation but observer saw no deny lines (stage=operation, lane=scenario, hypothesis). SBPL apply ok; none baseline ok.
  - Direct host Downloads (`downloads_direct_6b6d6d71bb48`): entitlements run reaches operation and observer recorded deny line (stage=operation, lane=scenario, mapped). SBPL apply ok; none baseline ok.

## Evidence & artifacts

- Reliability matrix summary: `book/evidence/experiments/runtime-final-final/suites/deny-delay-detail/out/reliability_summary.txt`.
- Reliability matrix JSON: `book/evidence/experiments/runtime-final-final/suites/deny-delay-detail/out/reliability_matrix.json`.
- Example external observer bundle: `book/evidence/experiments/runtime-final-final/suites/deny-delay-detail/out/matrix-external-2-85679cc9-03ea-4698-827d-de746ee5de2b/manifest.json`.
- Example manual observer bundle: `book/evidence/experiments/runtime-final-final/suites/deny-delay-detail/out/matrix-manual-2-8905ab2d-bd8b-4786-807e-3c87cfc8af84/manifest.json`.
- Capture failure evidence (`missing child_pid`): `book/evidence/experiments/runtime-final-final/suites/deny-delay-detail/out/matrix-capture-1-d3c2d691-adec-4f15-a307-221bcb0ed5c4/logs/deny-delay-detail_capture_matrix-capture-1-d3c2d691-adec-4f15-a307-221bcb0ed5c4.minimal.downloads_rw_probe.downloads_rw.json`.
- Tri-run comparison (openSession failure evidence): `book/evidence/experiments/runtime-final-final/suites/deny-delay-detail/out/compare/downloads_direct_3ba22aa95682/comparison.json`.
- Tri-run comparison (path-class Downloads, no deny lines): `book/evidence/experiments/runtime-final-final/suites/deny-delay-detail/out/compare/downloads_direct_a11650ccf1be/comparison.json`.
- Tri-run comparison (direct host Downloads, deny lines observed): `book/evidence/experiments/runtime-final-final/suites/deny-delay-detail/out/compare/downloads_direct_6b6d6d71bb48/comparison.json`.

## Risks / blockers

- Capture observer mode currently blocked by missing child PID; denies are not captured.
- OpenSession failure appears intermittent; not reproducible after follow-on runs (still recorded as hypothesis evidence).
- SBPL apply gates remain a risk, but the latest comparison shows apply success (no gate).

## Next steps

- Investigate the XPC openSession failure path in PolicyWitness (why the probe service lookup is sandbox-restricted).
- Find a baseline path or path-class that is writable without triggering host permissions, then re-run the tri-run comparison.
- Decide whether to disable capture mode until child PID capture is restored, and default to external observer mode.