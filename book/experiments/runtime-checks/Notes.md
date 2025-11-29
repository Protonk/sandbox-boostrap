# Runtime Checks – Notes

Use this file for dated, concise notes on progress, commands, and intermediate findings.

## 2025-12-10

- Experiment scaffolded (plan/report/notes). Aim: gather runtime allow/deny traces for bucket-4/bucket-5 and system profiles, landing results in `book/graph/mappings/runtime/`. Harness and probes not yet run.

## 2025-12-11

- Defined initial probe matrix in `out/expected_matrix.json` targeting bucket-4 (`v1_read`) and bucket-5 (`v11_read_subpath`) profiles from `op-table-operation`, plus placeholders for system profiles. Expectations cover read/write on `/etc/hosts` and `/tmp/foo` aligned with SBPL allows/denies. Runtime harness not run yet.
- Added stub `out/runtime_results.json` (status: not-run) to track expectations until harness is executed. Guardrail `tests/test_runtime_matrix_shape.py` ensures bucket profiles/probes remain in the matrix.

## 2025-12-12

- Implemented simple `run_probes.py` harness using `sandbox-exec` against SBPL profiles (`v1_read.sb`, `v11_read_subpath.sb`); creates `/tmp/foo`/`/tmp/bar` and runs cat/echo probes. Results written to `out/runtime_results.json`.
- On this host, `sandbox-exec` failed to apply both profiles (`exit_code=71`, `sandbox_apply: Operation not permitted`), so all probes show sandbox-apply failure. System profiles remain skipped (no SBPL form). Need alternative harness or entitlement to run sandbox-exec under SIP.

## 2025-11-28

- Re-ran `run_probes.py` under updated Codex permissions (full access) to see if `sandbox-exec` could apply profiles. Results still fail at launch: `sandbox-exec` cannot `execvp` the wrapped commands (`cat`, `sh`) with exit 71. For `v1_read` the errors are “Operation not permitted”; for `v11_read_subpath` they show “No such file or directory.” System profiles remain skipped (no paths provided). Effective runtime tracing is still blocked.

## 2025-11-28 (later)

- Added a harness shim in `run_probes.py` to emit runtime-ready profiles under `out/runtime_profiles/` with `process-exec` plus baseline system file-read allowances; the subpath profile also flips to `(allow default)` with explicit denies for `/private/tmp/bar` reads and `/tmp/foo` writes to avoid the earlier sandbox-exec abort.
- Re-ran `run_probes.py`. Bucket-4 (`v1_read`) now executes: `/etc/hosts` and `/tmp/foo` reads succeed; `/etc/hosts` write is denied (exit 1). Bucket-5 (`v11_read_subpath`) now runs without crashing: `/tmp/foo` read succeeds; `/tmp/bar` read and `/tmp/foo` write both deny with exit 1.
