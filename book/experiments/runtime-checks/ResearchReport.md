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
- Initial expected probe matrix written to `out/expected_matrix.json` covering bucket-4 (`v1_read`) and bucket-5 (`v11_read_subpath`) synthetic profiles with SBPL-aligned allow/deny expectations; system profiles listed as placeholders. Runtime harness still pending.
- Stub runtime results recorded in `out/runtime_results.json` (status: not-run) to track expectations; guardrail `tests/test_runtime_matrix_shape.py` ensures matrix shape persists.
- First harness attempt via `run_probes.py` using `sandbox-exec` on SBPL profiles (`v1_read.sb`, `v11_read_subpath.sb`) failed on this host: `sandbox_apply: Operation not permitted` (exit code 71) for all probes. System profiles remain skipped. Need alternative runtime mechanism to proceed under SIP.
- Re-ran `run_probes.py` with Codex full-access permissions; `sandbox-exec` still cannot launch the wrapped commands (exit 71). Errors now report `execvp()` failures (`Operation not permitted` for `v1_read` probes, `No such file or directory` for `v11_read_subpath` probes). System profiles remain skipped due to missing SBPL paths. Runtime evidence remains unavailable until a different harness or privilege path is used.

## Expected outcomes

- Runtime trace files keyed by profile and probe.
- A small guardrail to rerun representative bucket-4/bucket-5 checks.
- Notes on any mismatches between runtime behavior and decoder expectations.
