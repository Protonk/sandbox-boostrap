# Report

## Purpose
Frontier runtime probes for system-profile op gaps, anchor-backed filters, and a controlled unknown-op sample.

## Baseline & scope
- world_id: sonoma-14.4.1-23E224-arm64-dyld-2c0602c5
- Evidence is scoped to this host; no cross-host claims.

## Status
- status: partial (scaffolded; run pending)

## Evidence & artifacts
- Plan: `book/evidence/experiments/runtime-final-final/suites/runtime-frontiers/plan.json`
- Registry: `book/evidence/experiments/runtime-final-final/suites/runtime-frontiers/registry/{probes,profiles}.json`
- Profiles: `book/evidence/experiments/runtime-final-final/suites/runtime-frontiers/sb/*.sb`

## How to run
Run via the runtime CLI and treat the run-scoped bundle as the authority (`out/LATEST` points to the most recent committed run):

```sh
python -m book.api.runtime run \
  --plan book/evidence/experiments/runtime-final-final/suites/runtime-frontiers/plan.json \
  --channel launchd_clean \
  --out book/evidence/experiments/runtime-final-final/suites/runtime-frontiers/out
```

## Next steps
- Run the plan in a clean channel and capture `runtime_results.json` + `runtime_events.normalized.json`.
- Review mismatches and policy-layer/TCC attribution in normalized observations.
