# Matrix Runs

This document organizes the shrink-trace matrix into small, predictable run sets and records both expected and observed timing for each run under `out/matrix`.

Expected timing is derived from historical filesystem mtime spans (approximate). Observed timing is pulled from `run.json` timing fields for runs executed after explicit timers were added.
Precise timings live in each run’s `run.json`.

## Proposed run sets (sharded)

**Smoke (fast sanity)**
- Focus: confirm trace + shrink pipeline still works on the baseline fixture.
- Runs:
  - `sandbox_target_dyld1_netparsed_streak2`

**Core (behavior coverage)**
- Focus: baseline + dyld contrast + required network + subprocess.
- Runs:
  - `sandbox_target_dyld1_netparsed_streak2`
  - `sandbox_target_dyld0_netparsed_streak2`
  - `sandbox_net_required_dyld1_netparsed_streak2`
  - `sandbox_spawn_dyld1_netparsed_streak2`

**Extended (diagnostics and sensitivity)**
- Focus: streak sensitivity and failure modes (network drop, dyld off).
- Runs:
  - `sandbox_target_dyld1_netparsed_streak3`
  - `sandbox_target_dyld1_netdrop_streak2`
  - `sandbox_net_required_dyld1_netdrop_streak2`
  - `sandbox_net_required_dyld0_netparsed_streak2`
  - `sandbox_spawn_dyld0_netparsed_streak2`
  - `sandbox_spawn_dyld1_netdrop_streak2`

Next step (implementation): encode these sets in a small manifest (for example `scripts/matrix_runs.json`) and teach `scripts/run_matrix.sh` to accept `RUN_SET=smoke|core|extended`, skipping runs that already have `run.json`.

## Expected timing (planning, approximate)

| run | fixture | dyld_import | network_rules | success_streak | trace_status | shrink_status | expected_s |
| --- | --- | --- | --- | --- | --- | --- | --- |
| sandbox_net_required_dyld0_netdrop_streak2 | sandbox_net_required | 0 | drop | 2 | no_new_rules | skipped | 61.0 |
| sandbox_net_required_dyld0_netdrop_streak3 | sandbox_net_required | 0 | drop | 3 | no_new_rules | skipped | 30.2 |
| sandbox_net_required_dyld0_netparsed_streak2 | sandbox_net_required | 0 | parsed | 2 | success | success | 60.8 |
| sandbox_net_required_dyld0_netparsed_streak3 | sandbox_net_required | 0 | parsed | 3 | success | success | 67.0 |
| sandbox_net_required_dyld1_netdrop_streak2 | sandbox_net_required | 1 | drop | 2 | no_new_rules | skipped | 34.4 |
| sandbox_net_required_dyld1_netdrop_streak3 | sandbox_net_required | 1 | drop | 3 | no_new_rules | skipped | 27.7 |
| sandbox_net_required_dyld1_netparsed_streak2 | sandbox_net_required | 1 | parsed | 2 | success | success | 63.5 |
| sandbox_net_required_dyld1_netparsed_streak3 | sandbox_net_required | 1 | parsed | 3 | success | success | 63.4 |
| sandbox_spawn_dyld0_netdrop_streak2 | sandbox_spawn | 0 | drop | 2 | success | success | 57.2 |
| sandbox_spawn_dyld0_netdrop_streak3 | sandbox_spawn | 0 | drop | 3 | success | success | 44.9 |
| sandbox_spawn_dyld0_netparsed_streak2 | sandbox_spawn | 0 | parsed | 2 | success | success | 63.7 |
| sandbox_spawn_dyld0_netparsed_streak3 | sandbox_spawn | 0 | parsed | 3 | no_new_rules | skipped | 27.5 |
| sandbox_spawn_dyld1_netdrop_streak2 | sandbox_spawn | 1 | drop | 2 | success | success | 49.8 |
| sandbox_spawn_dyld1_netdrop_streak3 | sandbox_spawn | 1 | drop | 3 | success | success | 56.3 |
| sandbox_spawn_dyld1_netparsed_streak2 | sandbox_spawn | 1 | parsed | 2 | no_new_rules | skipped | 20.8 |
| sandbox_spawn_dyld1_netparsed_streak3 | sandbox_spawn | 1 | parsed | 3 | success | success | 56.6 |
| sandbox_target_dyld0_netdrop_streak2 | sandbox_target | 0 | drop | 2 | success | success | 49.8 |
| sandbox_target_dyld0_netdrop_streak3 | sandbox_target | 0 | drop | 3 | success | success | 56.8 |
| sandbox_target_dyld0_netparsed_streak2 | sandbox_target | 0 | parsed | 2 | success | success | 64.6 |
| sandbox_target_dyld0_netparsed_streak3 | sandbox_target | 0 | parsed | 3 | success | success | 84.2 |
| sandbox_target_dyld1_netdrop_streak2 | sandbox_target | 1 | drop | 2 | success | success | 49.8 |
| sandbox_target_dyld1_netdrop_streak3 | sandbox_target | 1 | drop | 3 | success | success | 50.1 |
| sandbox_target_dyld1_netparsed_streak2 | sandbox_target | 1 | parsed | 2 | success | success | 50.1 |
| sandbox_target_dyld1_netparsed_streak3 | sandbox_target | 1 | parsed | 3 | success | success | 50.8 |

## Observed timing (explicit timers)

| run | fixture | dyld_import | network_rules | success_streak | trace_status | shrink_status | observed_s | end_utc |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| sandbox_net_required_dyld0_netdrop_streak2 | sandbox_net_required | 0 | drop | 2 | no_new_rules | skipped | n/a | n/a |
| sandbox_net_required_dyld0_netdrop_streak3 | sandbox_net_required | 0 | drop | 3 | no_new_rules | skipped | n/a | n/a |
| sandbox_net_required_dyld0_netparsed_streak2 | sandbox_net_required | 0 | parsed | 2 | success | success | n/a | n/a |
| sandbox_net_required_dyld0_netparsed_streak3 | sandbox_net_required | 0 | parsed | 3 | success | success | n/a | n/a |
| sandbox_net_required_dyld1_netdrop_streak2 | sandbox_net_required | 1 | drop | 2 | no_new_rules | skipped | n/a | n/a |
| sandbox_net_required_dyld1_netdrop_streak3 | sandbox_net_required | 1 | drop | 3 | no_new_rules | skipped | n/a | n/a |
| sandbox_net_required_dyld1_netparsed_streak2 | sandbox_net_required | 1 | parsed | 2 | success | success | n/a | n/a |
| sandbox_net_required_dyld1_netparsed_streak3 | sandbox_net_required | 1 | parsed | 3 | success | success | n/a | n/a |
| sandbox_spawn_dyld0_netdrop_streak2 | sandbox_spawn | 0 | drop | 2 | success | success | n/a | n/a |
| sandbox_spawn_dyld0_netdrop_streak3 | sandbox_spawn | 0 | drop | 3 | success | success | n/a | n/a |
| sandbox_spawn_dyld0_netparsed_streak2 | sandbox_spawn | 0 | parsed | 2 | success | success | n/a | n/a |
| sandbox_spawn_dyld0_netparsed_streak3 | sandbox_spawn | 0 | parsed | 3 | no_new_rules | skipped | n/a | n/a |
| sandbox_spawn_dyld1_netdrop_streak2 | sandbox_spawn | 1 | drop | 2 | success | success | n/a | n/a |
| sandbox_spawn_dyld1_netdrop_streak3 | sandbox_spawn | 1 | drop | 3 | success | success | n/a | n/a |
| sandbox_spawn_dyld1_netparsed_streak2 | sandbox_spawn | 1 | parsed | 2 | no_new_rules | skipped | n/a | n/a |
| sandbox_spawn_dyld1_netparsed_streak3 | sandbox_spawn | 1 | parsed | 3 | success | success | n/a | n/a |
| sandbox_target_dyld0_netdrop_streak2 | sandbox_target | 0 | drop | 2 | success | success | n/a | n/a |
| sandbox_target_dyld0_netdrop_streak3 | sandbox_target | 0 | drop | 3 | success | success | n/a | n/a |
| sandbox_target_dyld0_netparsed_streak2 | sandbox_target | 0 | parsed | 2 | success | success | n/a | n/a |
| sandbox_target_dyld0_netparsed_streak3 | sandbox_target | 0 | parsed | 3 | success | success | n/a | n/a |
| sandbox_target_dyld1_netdrop_streak2 | sandbox_target | 1 | drop | 2 | success | success | n/a | n/a |
| sandbox_target_dyld1_netdrop_streak3 | sandbox_target | 1 | drop | 3 | success | success | n/a | n/a |
| sandbox_target_dyld1_netparsed_streak2 | sandbox_target | 1 | parsed | 2 | success | success | 50.479 | 2025-12-25T23:16:55Z |
| sandbox_target_dyld1_netparsed_streak3 | sandbox_target | 1 | parsed | 3 | success | success | n/a | n/a |

If a run is missing, re-run only that label using `OUT_DIR=./out/matrix/<label> ./scripts/run_workflow.sh` with the corresponding knobs, then regenerate this table.
