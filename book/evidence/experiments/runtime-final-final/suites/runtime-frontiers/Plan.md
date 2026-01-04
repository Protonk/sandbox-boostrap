# Plan

## Purpose
Expand runtime probe coverage along three frontiers: system-profile ops with zero runtime coverage, anchor-backed filters with typed literals, and a small unknown-op sample.

## Baseline & scope
- world_id: sonoma-14.4.1-23E224-arm64-dyld-a3a840f9
- Use ops/filters from `book/integration/carton/bundle/relationships/mappings/vocab/{ops,filters}.json`.
- Profiles in `sb/` are deny-default with targeted allow rules.

## Work
1. Run `python -m book.api.runtime run --plan book/evidence/experiments/runtime-final-final/suites/runtime-frontiers/plan.json --channel launchd_clean --out book/evidence/experiments/runtime-final-final/suites/runtime-frontiers/out`.
2. Emit a promotion packet once the run is promotable.
3. Review mismatches and record any apply-gate or TCC confounders.
