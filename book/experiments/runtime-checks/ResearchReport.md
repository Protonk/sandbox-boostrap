# Runtime Checks – Research Report (Sonoma / macOS 14.4.1)

## Purpose

Validate that runtime allow/deny behavior for selected profiles matches decoder-derived expectations, especially around bucket-4 vs bucket-5 distinctions and canonical system profiles. Capture reproducible traces under `book/graph/mappings/runtime/` and add guardrails.

## Baseline and scope

- Host: macOS 14.4.1 (23E224), Apple Silicon, SIP enabled.
- Target profiles:
  - Canonical system blobs (`airlock.sb.bin`, `bsd.sb.bin`, `sample.sb.bin`).
  - Representative bucket-4 and bucket-5 synthetic profiles from `op-table-operation`.
- Inputs: decoder outputs (bucket assignments, tag signatures) and vocab mappings in `book/graph/mappings/`.
- Harness: planned use of `sandbox-exec` (SBPL source or compiled blobs) with small driver scripts for filesystem, mach, and network probes.
- Output location: `book/graph/mappings/runtime/`.

## Plan (summary)

1. Define probes and expected outcomes per profile based on decoder outputs.
2. Run runtime probes via local harness (runner/reader) and wrapper blob mode; capture success/errno and logs.
3. Compare runtime results to expectations; add guardrail script covering representative cases.

## Current status

- Experiment scaffolded (this report, Plan, Notes).
- Expected probe matrix in `out/expected_matrix.json` covers bucket-4 (`v1_read`) and bucket-5 (`v11_read_subpath`) synthetic profiles, runtime shapes (`allow_all`, `metafilter_any`), and system blobs (`airlock`, `bsd`) flagged for blob mode.
- Harness now prefers local shims and wrapper: `sandbox_runner`/`sandbox_reader` succeed for bucket profiles and runtime shapes; metafilter_any stabilized by adding `/private/tmp` literals and reader mode.
- `sys:airlock`/`bsd` via blob: `airlock` returns `EPERM` even when recompiled from SBPL; `bsd` applies when compiled/SBPL but failed in one wrapper run due to execvp; SBPL path remains usable for `bsd` only. Treat `airlock` as expected-fail on this host; use SBPL/recompiled `bsd` if running system probes.

## Expected outcomes

- Runtime trace files keyed by profile and probe.
- A small guardrail to rerun representative bucket-4/bucket-5 checks.
- Notes on any mismatches between runtime behavior and decoder expectations.
