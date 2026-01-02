# Hardened Runtime – Research Report

## Purpose
Provide a clean, provenance-stamped decision-stage runtime lane for non-VFS sandbox operations on this host. The experiment is built around two host-bound hypotheses: (1) policy evaluation is operation-based and filter-driven, and (2) acquisition timing (before vs after sandbox apply) shapes enforcement. Both are treated as hypotheses under exploration until host evidence is captured.

## Baseline & scope
- World: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5` (`book/world/sonoma-14.4.1-23E224-arm64/world.json`).
- Non-VFS operations only (mach/XPC, sysctl, IOKit, process-info, system-socket, notifications).
- VFS canonicalization is out-of-scope except as a recorded observation field when present in runtime events.

## Status
- **partial**: clean-channel run recorded with decision-stage events; signal-to-same-sandbox canary now succeeds with a deny control, while allow attempts for mach/sysctl/notifications/process-info still deny under the strict profiles and remain under exploration. Allow-canary profiles with `(allow default)` are now present as positive-evidence checks.

## Clean-channel success criteria (for promotable runs)
- `out/LATEST/run_manifest.json` reports `channel=launchd_clean` with `sandbox_check_self` and staging context.
- `out/LATEST/runtime_events.normalized.json` includes decision-stage events (not apply/preflight only).
- `out/LATEST/baseline_results.json` and `out/LATEST/oracle_results.json` are present and remain separate lanes.
- `out/LATEST/artifact_index.json` lists all core artifacts with digests and schema versions.

## Current probe families
- **mach-lookup** (global-name): allow/deny probes for a small service set to map decision-stage behavior.
- **sysctl-read** (sysctl-name): allow/deny probes for a small sysctl set to map decision-stage behavior.
- **notifications** (notification-name): darwin + distributed post probes with allow/deny pairs.
- **process-info-pidinfo**: allow-profile attempt vs deny profile using `proc_pidinfo` on self and pid 1.
- **signal** (same-sandbox target): canary allow/deny using a child process to exercise signal checks; “self” is not used as a deny control.

## Latest run summary
- `out/LATEST/run_manifest.json` reports `channel=launchd_clean` with staged root under `/private/tmp`.
- Decision-stage events are present in `out/LATEST/runtime_events.normalized.json`.
- `out/LATEST/baseline_results.json` shows unsandboxed success for mach/sysctl/notification/process-info probes, while sandboxed runs deny under the current profiles.
- Signal canary allow and deny both match expectations (control verified).

## Deliverables / expected outcomes
- Clean-channel run provenance (`out/LATEST/run_manifest.json`) and apply preflight (`out/LATEST/apply_preflight.json`).
- Baseline comparator (`out/LATEST/baseline_results.json`) recorded from unsandboxed probes.
- Decision-stage runtime outputs (`out/LATEST/runtime_results.json`, `out/LATEST/runtime_events.normalized.json`).
- Oracle lane (`out/LATEST/oracle_results.json`) separated from syscall-observed outcomes.
- Bounded mismatches (`out/LATEST/mismatch_packets.jsonl`) with enumerated `mismatch_reason`.
- Summary (`out/LATEST/summary.json`, `out/LATEST/summary.md`).
- Artifact index (`out/LATEST/artifact_index.json`) that pins paths, digests, and schema versions for the run.

## Evidence & artifacts
- SBPL sources: `book/evidence/experiments/hardened-runtime/sb/*.sb`.
- Clean channel: `python -m book.api.runtime run --plan book/evidence/experiments/hardened-runtime/plan.json --channel launchd_clean`.
- Plan template: `python -m book.api.runtime plan-build --template hardened-runtime --out book/evidence/experiments/hardened-runtime --overwrite` (plan-build skips expected_matrix.json by default; use `--write-expected-matrix` for a static snapshot).
- Outputs: `book/evidence/experiments/hardened-runtime/out/LATEST/` (see Deliverables).
- Runtime tooling inventory: `book/evidence/experiments/hardened-runtime/other_runtime_inventory.json` (regenerated after probe migration to `book/api/runtime/native/probes`).

## Claims and limits
- Runtime claims remain **partial** while mismatches persist; mismatch packets keep the boundary explicit.
- Oracle results are a separate lane and must not be merged into syscall-observed evidence.
- This experiment does not attempt to explain VFS canonicalization; it only records path observations when present.
- Dependency denials are recorded explicitly (`decision_path`, `first_denial_op`, `first_denial_filters`) and are not treated as primary-op evidence.

## Next steps
- Refresh the clean-channel run after each new probe family to keep decision-stage evidence current.
- Add IOKit, process-info, and system-socket probe families once notifications are stable.
- Add acquire-before vs acquire-after variants to bound the warmup boundary for non-file resources.
