# Runtime Checks – Research Report

## Purpose
Validate that runtime allow/deny behavior for selected profiles matches decoder-derived expectations, especially around bucket‑4 vs bucket‑5 distinctions and canonical system profiles. Capture reproducible traces under `book/evidence/graph/mappings/runtime/` and add guardrails.

## Baseline & scope
- World: Sonoma baseline from `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
- Target profiles:
  - Canonical system blobs (`airlock.sb.bin`, `bsd.sb.bin`, `sample.sb.bin`).
  - Representative bucket-4 and bucket-5 synthetic profiles from `op-table-operation`.
- Inputs: decoder outputs (bucket assignments, tag signatures) and vocab mappings in `book/evidence/graph/mappings/`.
- Harness: plan-based runtime execution via `python -m book.api.runtime run --plan ... --channel ...` (runtime shims + bundle lifecycle).
- Output location: run-scoped bundles under `book/evidence/experiments/runtime-final-final/suites/runtime-checks/out/<run_id>/` (resolve via `out/LATEST`).

## How to run
Run via the runtime CLI and treat the committed bundle as the authority (`out/LATEST` points to the most recent committed run):

```sh
python -m book.api.runtime run \
  --plan book/evidence/experiments/runtime-final-final/suites/runtime-checks/plan.json \
  --channel launchd_clean \
  --out book/evidence/experiments/runtime-final-final/suites/runtime-checks/out
```

## Deliverables / expected outcomes
- Runtime trace files keyed by profile and probe.
  - A small guardrail to rerun representative bucket-4/bucket-5 checks.
  - Notes on any mismatches between runtime behavior and decoder expectations.
- Deliverables: plan/notes/report in this directory; run-scoped bundles under `out/<run_id>/`.
- Deliverables: bundle artifacts (`out/<run_id>/expected_matrix.json`, `out/<run_id>/runtime_results.json`, `out/<run_id>/runtime_events.normalized.json`, `out/<run_id>/artifact_index.json`).

## Plan & execution log
### Completed
- **Current status**
  - Experiment scaffolded (this Report, Plan, Notes).
  - Expected probe matrix in `out/LATEST/expected_matrix.json` covers bucket-4 (`v1_read`) and bucket-5 (`v11_read_subpath`) synthetic profiles, runtime shapes (`allow_all`, `metafilter_any`), and system blobs (`airlock`, `bsd`) flagged for blob mode (airlock marked expected-fail locally).
  - Harness is the runtime CLI (plan-based) using runtime shims (`book/api/runtime/native/sandbox_runner/{sandbox_runner,sandbox_reader}`) and the SBPL wrapper for blob mode when needed.
  - Mach/IOKit probe binaries moved to `book/api/runtime/native/probes` with a shared sandbox profile helper and local build script.
  - `sys:airlock`/`bsd`: `airlock` is apply-gated on this host baseline and is preflight-blocked by default (treat as expected-fail); `bsd` applies via SBPL/compiled blob (wrapper run hit execvp noise once). Use SBPL/recompiled `bsd` for system probes on this host.
  - Latest rerun executed via `python -m book.api.runtime run --plan book/evidence/experiments/runtime-final-final/suites/runtime-checks/plan.json --channel launchd_clean` (staged to `/private/tmp`); decision-stage outcomes are current for the runtime-checks matrix and only `sys:airlock` remains preflight-blocked. `out/LATEST/runtime_results.json` now carries seatbelt-callout markers (sandbox_check oracle lane) for file/mach probes.
  - Clean-channel runs now emit `out/LATEST/run_manifest.json` and `out/LATEST/apply_preflight.json` (sandbox_check self check + baseline metadata). Mapping generators require `channel=launchd_clean` before promoting decision-stage artifacts.
- **1) Scope and setup**
  - Identified target profiles: canonical system blobs (`airlock`, `bsd`, `sample`) and representative bucket-4/bucket-5 synthetic profiles (`v1_read`, `v11_read_subpath`) from `op-table-operation`.
  - Harness in place: runtime CLI uses the shared runtime shims and SBPL wrapper for blob-mode profiles.
- **2) Define probes and expectations**
  - Listed the operations and concrete probes for bucket-4 and bucket-5 profiles (e.g., `file-read*` on `/etc/hosts` and `/tmp/foo`, `file-write*` to `/etc/hosts` / `/tmp/foo`), captured in `out/LATEST/expected_matrix.json`.
- **3) Run runtime checks**
  - Plan execution runs via `python -m book.api.runtime run --plan book/evidence/experiments/runtime-final-final/suites/runtime-checks/plan.json --channel launchd_clean` and writes bundle artifacts under `out/<run_id>/`.
- **3) Run runtime checks (updates)**
  - `sandbox_runner`/`sandbox_reader` now work on this host: bucket-4/5, allow_all, and metafilter_any complete with expected/actual/match fields (metafilter fixed by adding /private/tmp literals and reader mode).
  - System profiles now run as compiled blobs through the wrapper; on this host `sandbox_apply` returns `EPERM` for airlock (even when recompiled); bsd works via SBPL/compiled blob. Adjust expectations accordingly; airlock treated as expected-fail locally.
- **4) Compare and guardrail**
  - Added a guardrail test (`book/tests/planes/runtime/test_runtime_matrix_shape.py`) that asserts matrix shape and the presence of bucket‑4/bucket‑5 probe definitions.
  - Recorded the current harness failure (`sandbox_apply: Operation not permitted`) and its implications in this Report and in `Notes.md`.

### Maintenance / rerun plan
If runtime checks are extended or revisited, reuse this outline:

1. **Scope and setup**
   - Confirm the host baseline (OS/build, SIP) in `book/world/.../world.json`, this Report, and `Notes.md` if more runtime work resumes.
   - Decide which profiles (synthetic bucket‑4/bucket‑5, `bsd`, and any others) are in scope.
2. **Define probes and expectations**
   - Refine expected allow/deny outcomes based on decoder bucket assignments and tag signatures; update `out/LATEST/expected_matrix.json` as needed.
3. **Run runtime checks**
   - Run plan-based probes via `python -m book.api.runtime run --plan book/evidence/experiments/runtime-final-final/suites/runtime-checks/plan.json --channel launchd_clean` and read results from `out/LATEST/runtime_results.json`.
   - Treat `EPERM` from `sandbox_apply` as a first-class outcome; adjust expectations for profiles like `airlock` that cannot be applied on this host.
4. **Compare and guardrail**
   - Compare runtime results to the expected matrix and extend guardrails from matrix-shape checks to a small set of concrete allow/deny outcomes once harness stability is acceptable.

## Evidence & artifacts
- Probe matrix in `book/evidence/experiments/runtime-final-final/suites/runtime-checks/out/LATEST/expected_matrix.json` describing profiles, probes, and expected outcomes.
- Runtime results in `book/evidence/experiments/runtime-final-final/suites/runtime-checks/out/LATEST/runtime_results.json` and `book/evidence/experiments/runtime-final-final/suites/runtime-checks/out/LATEST/runtime_events.normalized.json`.
- Clean-channel manifests: `book/evidence/experiments/runtime-final-final/suites/runtime-checks/out/LATEST/run_manifest.json` (provenance bundle) and `book/evidence/experiments/runtime-final-final/suites/runtime-checks/out/LATEST/apply_preflight.json` (sandbox_check self check).
- Sandbox_check callouts: `book/evidence/experiments/runtime-final-final/suites/runtime-checks/out/LATEST/runtime_results.json` includes `seatbelt_callouts` markers for file/mach probes (oracle lane only).
- Runtime execution via `python -m book.api.runtime run --plan book/evidence/experiments/runtime-final-final/suites/runtime-checks/plan.json --channel launchd_clean`; shims live in `book/api/runtime/native/sandbox_runner`, probes in `book/api/runtime/native/probes`, wrapper in `book/tools/sbpl/wrapper`.
- Guardrail test `book/integration/tests/runtime/test_runtime_matrix_shape.py` asserting the presence and shape of the expected matrix.

## Blockers / risks
- On this Sonoma host, `sandbox_apply` returns `EPERM` for `airlock` even when recompiled from SBPL, so platform profiles cannot yet be exercised directly in blob mode.
- Harness behavior is still somewhat fragile (earlier `sandbox-exec` attempts failed under SIP; wrapper/harness plumbing has seen multiple revisions), so results need careful interpretation and may not generalize.
- `sys:airlock` remains preflight-blocked on this world, so airlock runtime evidence is still blocked even when other profiles are decision-stage.

## Next steps
- Re-run or refine runtime checks via the runtime CLI, focusing on synthetic bucket-4/bucket-5 profiles and `bsd` rather than `airlock`.
- If practical, repeat selected probes on a host where platform blobs can be applied successfully, or codify “expected-fail” behavior for `airlock` as part of this host’s baseline.
- Extend guardrails from matrix-shape checks to a small set of concrete allow/deny outcomes once harness stability is acceptable.
- Use the runtime clean channel (staged to `/private/tmp`) when running from a sandboxed parent to ensure decision-stage runs.
