# Plan

## Question
- Can we reproduce a trace-then-shrink workflow that converges on a minimal SBPL profile for a deterministic fixture on this host?

## Hypothesis
- The fixture should converge within a small number of iterations and shrink should remove rules associated with optional noise. This is a working assumption, not a host witness.

## Success criteria
- `trace_instrumented.sh` reaches a stop condition and writes `metrics.tsv` and per-iteration logs.
- `shrink.sh` produces `profile.sb.shrunk` and `sandbox-exec -f profile.sb.shrunk sandbox_target` returns 0.
- Outputs are reproducible under the Sonoma baseline.

## Approach
1) Build the fixture (`scripts/build_fixture.sh`).
2) Run the instrumented trace (`scripts/trace_instrumented.sh`) via `scripts/run_workflow.sh`.
3) Shrink the resulting profile with the upstream shrinker.
4) Summarize convergence and rule counts with `scripts/summarize_metrics.sh`.

## Status
- Not started (scaffolding only; no runs yet).
