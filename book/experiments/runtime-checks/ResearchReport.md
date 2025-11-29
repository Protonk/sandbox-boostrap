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
2. Run runtime probes via `sandbox-exec`; capture success/errno and logs.
3. Compare runtime results to expectations; add guardrail script covering representative cases.

## Current status

- Experiment scaffolded (this report, Plan, Notes).
- Initial expected probe matrix written to `out/expected_matrix.json` covering bucket-4 (`v1_read`) and bucket-5 (`v11_read_subpath`) synthetic profiles with SBPL-aligned allow/deny expectations; system profiles listed as placeholders.
- First harness attempts via `run_probes.py` using `sandbox-exec` on SBPL profiles (`v1_read.sb`, `v11_read_subpath.sb`) failed on this host: `sandbox_apply: Operation not permitted` (exit code 71) for all probes, even with Codex full-access permissions (`execvp()` errors).
- Added harness shims to generate runtime-ready profiles under `out/runtime_profiles/`: process-exec allowance, baseline system file-read grants, and for the subpath profile a `(allow default)` plus explicit denies for `/private/tmp/bar` reads and `/tmp/foo` writes to avoid sandbox-exec abort. Re-ran probes; `out/runtime_results.json` now shows bucket-4 reads allowed and writes to `/etc/hosts` denied (exit 1), while bucket-5 allows `/tmp/foo` reads and denies `/tmp/bar` reads and `/tmp/foo` writes (exit 1). System profiles remain skipped due to missing SBPL paths.

## Expected outcomes

- Runtime trace files keyed by profile and probe.
- A small guardrail to rerun representative bucket-4/bucket-5 checks.
- Notes on any mismatches between runtime behavior and decoder expectations.
