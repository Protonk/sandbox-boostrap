# Anchor ↔ Filter Runtime Discriminators — Report

## Purpose
Provide runtime discriminator bundles (and promotion packets) for anchor → filter bindings used by the field2 mapping surface. The canonical mapping remains in `book/evidence/experiments/field2-final-final/anchor-filter-map/`.

## Baseline & scope
- World: `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
- Evidence: runtime bundles under `out/<run_id>/` and a promotion packet under `book/evidence/experiments/runtime-final-final/evidence/packets/`.

## How to run
Run the main plan (and the iokit-class variant) via the runtime CLI; commit the run-scoped bundles and update `out/LATEST`:

```sh
python -m book.api.runtime run \
  --plan book/evidence/experiments/runtime-final-final/suites/anchor-filter-map/plan.json \
  --channel launchd_clean \
  --out book/evidence/experiments/runtime-final-final/suites/anchor-filter-map/out
```

```sh
python -m book.api.runtime run \
  --plan book/evidence/experiments/runtime-final-final/suites/anchor-filter-map/iokit-class/plan.json \
  --channel launchd_clean \
  --out book/evidence/experiments/runtime-final-final/suites/anchor-filter-map/iokit-class/out
```

## Notes
See the field2 mapping report for interpretation and mapping decisions.
