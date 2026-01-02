# Plan

## Current state (summary)

- The trace + shrink workflow converges for the baseline, required-network, subprocess, and minimal-loader fixtures on this host (partial; see `Report.md`).
- Two-state shrink preserves first-run and repeat-run requirements, and can remove intentionally unused rules.
- Matrix results show sensitivity to dyld import and network rule mode.

## Known brittleness

- Some runs stop early (`no_new_rules`) and only converge on rerun.
- Removing `dyld-support.sb` can trigger `SIGABRT` during shrink attempts.
- Matrix runs can exceed default timeouts.

## Next questions and what they teach

1) **How much deny noise is ambient vs fixture-driven?**
   - Plan: compare `DENY_SCOPE=pid` vs `DENY_SCOPE=all` on the same fixtures.
   - Teaches: how much the sandbox denial surface is attributable to child processes or background activity.

2) **What minimal loader allowances are required before user code runs?**
   - Plan: isolate dyld imports and trace `sandbox_min` variants with and without dyld support.
   - Teaches: early loader dependencies and the boundary between apply-time and runtime denials.

3) **Which network deny shapes remain unparseable?**
   - Plan: collect `bad_rules.txt` patterns from the matrix and categorize by address shape.
   - Teaches: practical constraints on SBPL network filters for this host.

4) **How stable is convergence under different streak thresholds?**
   - Plan: repeat matrix with `SUCCESS_STREAK` variations and compare convergence and profile size.
   - Teaches: sensitivity of deny-based bootstrapping to log timing and non-determinism.
