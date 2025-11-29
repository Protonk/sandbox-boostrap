# Runtime Checks – Notes

Use this file for dated, concise notes on progress, commands, and intermediate findings.

## 2025-12-10

- Experiment scaffolded (plan/report/notes). Aim: gather runtime allow/deny traces for bucket-4/bucket-5 and system profiles, landing results in `book/graph/mappings/runtime/`. Harness and probes not yet run.

## 2025-12-11

- Defined initial probe matrix in `out/expected_matrix.json` targeting bucket-4 (`v1_read`) and bucket-5 (`v11_read_subpath`) profiles from `op-table-operation`, plus placeholders for system profiles. Expectations cover read/write on `/etc/hosts` and `/tmp/foo` aligned with SBPL allows/denies. Runtime harness not run yet.
