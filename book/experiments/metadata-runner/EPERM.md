# EPERM handling for metadata-runner

## What failed
- Runtime probes for metadata ops returned `errno=EPERM` even when the SBPL contained matching literals:
  - `metadata_alias_only` denied all `lstat`/`chmod` requests across alias and canonical paths.
  - `metadata_canonical_only` and `metadata_both_paths` allowed canonical paths but still returned `EPERM` on alias paths, unlike the data-op canonicalization experiment.
- `sandbox-exec` was not usable as a fallback runner; invoking it with these SBPL snippets failed with `exit 71` (`execvp() ... failed: No such file or directory`) on this host.

## Apply gates vs. syscall failures
- The Swift runner uses `sandbox_init` on SBPL text to avoid the known `sandbox_apply` gate for blobs. In these runs `apply_rc=0` and `apply_mode=sbpl`, so failures are not apply gates.
- The `EPERM` values come from the metadata syscalls themselves (`lstat` for `file-read-metadata`, `chmod` for `file-write*` proxy).
- Control sanity: with `(allow default)` SBPL, the runner returns `errno=0` for metadata ops, confirming the runner and syscalls work when the policy allows them.

## Repro steps (current state)
1) Ensure fixtures exist (driver does this): canonical files at `/private/tmp/{foo,bar,nested/child}` and `/private/var/tmp/canon`, writable by the user.
2) Build and run the matrix:
   - `python3 book/experiments/metadata-runner/run_metadata.py`
   - Inspect `out/runtime_results.json` for `status`/`errno` and `out/decode_profiles.json` for anchor presence.
3) Quick single-probe repro:  
   - `clang -c book/api/runtime/native/seatbelt_callout_shim.c -o /tmp/seatbelt_callout_shim.o`  
   - `swiftc book/experiments/metadata-runner/metadata_runner.swift book/api/runtime/native/ToolMarkers.swift /tmp/seatbelt_callout_shim.o -o /tmp/metadata_runner_test`  
   - `cat > /tmp/simple_meta.sb <<'EOF'\n(version 1)\n(deny default)\n(allow file-read* (literal "/private/tmp/foo"))\n(allow file-read-metadata (literal "/private/tmp/foo"))\nEOF`  
   - `/tmp/metadata_runner_test --sbpl /tmp/simple_meta.sb --op file-read-metadata --path /private/tmp/foo` → `OK`  
   - `/tmp/metadata_runner_test --sbpl /tmp/simple_meta.sb --op file-read-metadata --path /tmp/foo` → `EPERM`

## Interpretation and open questions
- The persistent `EPERM` on alias paths suggests metadata ops are not benefiting from the alias → canonical rewriting seen for data read/write in `vfs-canonicalization`. This now holds across multiple syscalls (`lstat`, `getattrlist`, `chmod`, `utimes`).
- Expanded coverage (`lstat`, `getattrlist`, `setattrlist`, `fstat`, `chmod`, `utimes`, `fchmod`, `futimes`, `lchown`, `fchown`, `fchownat`, `lutimes`) and anchor variants (literal, subpath, regex) shows anchor-sensitive alias handling: literal-both still denies aliases; subpath-both and regex-both allow aliases; alias-only profiles continue to deny all. `setattrlist` returns `EINVAL` on canonical paths and `EPERM` on aliases. Attrlist payload choices (cmn, cmn-name, cmn-times, file-size) did not change these patterns.
- Structural check: only `/tmp/foo` appears in `anchor_filter_map.json`; literal profiles expose it with field2=6 (subset of expected {0,4,5,6}); regex/subpath profiles don't surface `/tmp/foo` literals in the decoder, so they appear absent in the check. Treat this as partial alignment limited to literal anchors.

## Mitigation guidance for future agents
- Use SBPL via `sandbox_init` in this experiment; compiled blob + `sandbox_apply` is likely to hit apply gates on this host.
- Keep an allow-all SBPL on hand to sanity-check runner behavior when investigating new EPERMs.
- Document any syscall-specific behavior alongside the op name to avoid assuming uniform metadata handling across syscalls.
