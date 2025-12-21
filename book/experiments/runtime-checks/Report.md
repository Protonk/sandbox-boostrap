# Runtime Checks – Research Report

## Purpose
Validate that runtime allow/deny behavior for selected profiles matches decoder-derived expectations, especially around bucket‑4 vs bucket‑5 distinctions and canonical system profiles. Capture reproducible traces under `book/graph/mappings/runtime/` and add guardrails.

## Baseline & scope
- World: Sonoma baseline from `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
- Target profiles:
  - Canonical system blobs (`airlock.sb.bin`, `bsd.sb.bin`, `sample.sb.bin`).
  - Representative bucket-4 and bucket-5 synthetic profiles from `op-table-operation`.
- Inputs: decoder outputs (bucket assignments, tag signatures) and vocab mappings in `book/graph/mappings/`.
- Harness: planned use of `sandbox-exec` (SBPL source or compiled blobs) with small driver scripts for filesystem, mach, and network probes.
- Output location: `book/graph/mappings/runtime/`.

## Deliverables / expected outcomes
- Runtime trace files keyed by profile and probe.
  - A small guardrail to rerun representative bucket-4/bucket-5 checks.
  - Notes on any mismatches between runtime behavior and decoder expectations.
- Deliverables: plan/notes/report in this directory; `out/` for raw traces/logs.
- Deliverables: `out/expected_matrix.json` (profile × probe → expected verdict).
- Deliverables: `out/runtime_results.json` plus brief Notes.

## Plan & execution log
### Completed
- **Current status**
  - Experiment scaffolded (this Report, Plan, Notes).
  - Expected probe matrix in `out/expected_matrix.json` covers bucket-4 (`v1_read`) and bucket-5 (`v11_read_subpath`) synthetic profiles, runtime shapes (`allow_all`, `metafilter_any`), and system blobs (`airlock`, `bsd`) flagged for blob mode (airlock marked expected-fail locally).
  - Harness now prefers local shims and wrapper: `sandbox_runner`/`sandbox_reader` succeed for bucket profiles and runtime shapes; metafilter_any stabilized by adding `/private/tmp` literals and reader mode.
  - `sys:airlock`/`bsd`: `airlock` is apply-gated on this host baseline and is preflight-blocked by default (treat as expected-fail); `bsd` applies via SBPL/compiled blob (wrapper run hit execvp noise once). Use SBPL/recompiled `bsd` for system probes on this host.
  - Latest rerun executed under a more permissive host context (Codex harness `--yolo`); apply-stage EPERM cleared for the runtime-checks matrix and only `sys:airlock` remains preflight-blocked.
- **1) Scope and setup**
  - Identified target profiles: canonical system blobs (`airlock`, `bsd`, `sample`) and representative bucket-4/bucket-5 synthetic profiles (`v1_read`, `v11_read_subpath`) from `op-table-operation`.
  - Harness in place: `run_probes.py` prefers local shims (`sandbox_runner` / `sandbox_reader`) and now uses `book/api/SBPL-wrapper/wrapper --blob` for compiled profiles.
- **2) Define probes and expectations**
  - Listed the operations and concrete probes for bucket-4 and bucket-5 profiles (e.g., `file-read*` on `/etc/hosts` and `/tmp/foo`, `file-write*` to `/etc/hosts` / `/tmp/foo`), captured in `out/expected_matrix.json`.
- **3) Run runtime checks**
  - Implemented `run_probes.py` to execute filesystem probes under `sandbox-exec` for the selected SBPL profiles and write results to `out/runtime_results.json`.
  - Switched harness to prefer `sandbox_runner`/`sandbox_reader`; blob profiles now flow through `wrapper --blob`.
- **3) Run runtime checks (updates)**
  - `sandbox_runner`/`sandbox_reader` now work on this host: bucket-4/5, allow_all, and metafilter_any complete with expected/actual/match fields (metafilter fixed by adding /private/tmp literals and reader mode).
  - System profiles now run as compiled blobs through the wrapper; on this host `sandbox_apply` returns `EPERM` for airlock (even when recompiled); bsd works via SBPL/compiled blob. Adjust expectations accordingly; airlock treated as expected-fail locally.
- **4) Compare and guardrail**
  - Added a guardrail test (`tests/test_runtime_matrix_shape.py`) that asserts matrix shape and the presence of bucket‑4/bucket‑5 probe definitions.
  - Recorded the current harness failure (`sandbox_apply: Operation not permitted`) and its implications in this Report and in `Notes.md`.

### Maintenance / rerun plan
If runtime checks are extended or revisited, reuse this outline:

1. **Scope and setup**
   - Confirm the host baseline (OS/build, SIP) in `book/world/.../world-baseline.json`, this Report, and `Notes.md` if more runtime work resumes.
   - Decide which profiles (synthetic bucket‑4/bucket‑5, `bsd`, and any others) are in scope.
2. **Define probes and expectations**
   - Refine expected allow/deny outcomes based on decoder bucket assignments and tag signatures; update `out/expected_matrix.json` as needed.
3. **Run runtime checks**
   - Run filesystem (and other) probes via the wrapper-based harness and record results in `out/runtime_results.json`.
   - Treat `EPERM` from `sandbox_apply` as a first-class outcome; adjust expectations for profiles like `airlock` that cannot be applied on this host.
4. **Compare and guardrail**
   - Compare runtime results to the expected matrix and extend guardrails from matrix-shape checks to a small set of concrete allow/deny outcomes once harness stability is acceptable.

## Evidence & artifacts
- Probe matrix in `book/experiments/runtime-checks/out/expected_matrix.json` describing profiles, probes, and expected outcomes.
- Runtime results in `book/experiments/runtime-checks/out/runtime_results.json` from `run_probes.py` runs (where harnesses succeeded).
- Harness scripts (`run_probes.py`, `sandbox_runner`, `sandbox_reader`, and SBPL wrapper integration) under this directory and `book/api/SBPL-wrapper`.
- Guardrail test `tests/test_runtime_matrix_shape.py` asserting the presence and shape of the expected matrix.

## Blockers / risks
- On this Sonoma host, `sandbox_apply` returns `EPERM` for `airlock` even when recompiled from SBPL, so platform profiles cannot yet be exercised directly in blob mode.
- Harness behavior is still somewhat fragile (earlier `sandbox-exec` attempts failed under SIP; wrapper/harness plumbing has seen multiple revisions), so results need careful interpretation and may not generalize.
- Even on the more permissive host context (`--yolo`), `sys:airlock` remains preflight-blocked, so airlock runtime evidence is still blocked on this world.

## Next steps
- Re-run or refine runtime checks using the current wrapper-based harness, focusing on synthetic bucket-4/bucket-5 profiles and `bsd` rather than `airlock`.
- If practical, repeat selected probes on a host where platform blobs can be applied successfully, or codify “expected-fail” behavior for `airlock` as part of this host’s baseline.
- Extend guardrails from matrix-shape checks to a small set of concrete allow/deny outcomes once harness stability is acceptable.
