# Field2 Probe-Op-Structure Runtime Slice — Report

## Purpose
Host-bound runtime slice for anchor checks used by the field2 probe-op-structure experiment. This suite contains only the runtime plan, registry, and bundles.

## Baseline & scope
- World: `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
- Evidence: runtime bundles under `out/<run_id>/` (committed via `artifact_index.json`).

## How to run
Run the plan via the runtime CLI and commit the bundle under `out/<run_id>/`:

```sh
python -m book.api.runtime run \
  --plan book/evidence/experiments/runtime-final-final/suites/field2-probe-op-structure/plan.json \
  --channel launchd_clean \
  --out book/evidence/experiments/runtime-final-final/suites/field2-probe-op-structure/out
```

## Notes
Interpretation and structural context remain in `book/evidence/experiments/field2-final-final/probe-op-structure/Report.md`.
