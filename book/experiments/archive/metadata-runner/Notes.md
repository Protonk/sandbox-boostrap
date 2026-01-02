# Notes

- `file-write-metadata` is not in the SBPL vocabulary; metadata writes are exercised via `file-write*` using `chmod` in the runner.
- Swift runner (`book/api/runtime/native/metadata_runner/metadata_runner.swift`) uses `sandbox_init` with SBPL input and issues `lstat`/`getattrlist`/`setattrlist`/`fstat` (read-metadata) and `chmod`/`utimes`/`fchmod`/`futimes`/`lchown`/`fchown`/`fchownat`/`lutimes` (metadata write proxies), emitting JSON.
- `run_metadata.py` compiles SBPL probes, builds the runner, seeds fixtures via canonical paths, and runs the matrix across alias/canonical paths for both operations and all syscalls; outputs land in `out/runtime_results.json` and `out/decode_profiles.json`.
- Expanded syscall runs across anchor forms show anchor sensitivity: literal-both still only allows canonical paths; subpath-both and regex-both allow `/tmp/*` aliases but continue to deny `/var/tmp/canon`; alias-only profiles deny all; canonical-only profiles allow canonical paths. `setattrlist` returns `EINVAL` on canonical paths and `EPERM` on aliases. Attrlist payload variants (cmn, cmn-name, cmn-times, file-size) do not change the allow/deny pattern beyond the anchor form effects.
- Structural cross-checks for anchors and decoder fields moved to `book/experiments/field2-final-final/metadata-runner/` (field2-focused).
- Control sanity: `(allow default)` profile via the runner permits metadata operations, confirming the runner is behaving; targeted allows are what surface the alias/canonical divergence.
- Migrated the Swift runner source to `book/api/runtime/native/metadata_runner` and updated the driver to build via the shared build script.
- Local build attempt of `book/api/runtime/native/metadata_runner/build.sh` failed with Swift module cache permission errors and an SDK/compiler mismatch; the script itself is correct but the toolchain needs alignment to run.
- Unified runtime CLI run: `launchd_clean` bootstrap failed (launchctl exit 5); direct channel run succeeded and produced a committed bundle under `book/experiments/metadata-runner/out/<run_id>/`.
