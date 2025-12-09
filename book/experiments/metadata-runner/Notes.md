# Notes

- `file-write-metadata` is not in the SBPL vocabulary; metadata writes are exercised via `file-write*` using `chmod` in the runner.
- Swift runner (`metadata_runner.swift`) uses `sandbox_init` with SBPL input and issues `lstat` (read-metadata) and `chmod` (metadata write proxy), emitting JSON.
- `run_metadata.py` compiles SBPL probes, builds the runner, seeds fixtures via canonical paths, and runs the matrix across alias/canonical paths for both operations; outputs land in `out/runtime_results.json` and `out/decode_profiles.json`.
- First run: `metadata_canonical_only` and `metadata_both_paths` allow canonical requests (read-metadata + chmod) and deny alias requests; `metadata_alias_only` denies all. Alias literals did not grant access, unlike the data read/write canonicalization experiment.
- Control sanity: `(allow default)` profile via the runner permits metadata operations, confirming the runner is behaving; targeted allows are what surface the alias/canonical divergence.
