# SBPL ↔ Graph ↔ Runtime – Notes

Use this file for dated, concise notes on commands, hurdles, and intermediate results.

## 2026-01-XX

- Authored minimal profiles: `allow_all.sb`, `deny_all.sb`, `deny_except_tmp.sb`, `metafilter_any.sb` (param_path.sb exists but fails to compile without param injection).
- Compiled via `book/examples/sbsnarf/sbsnarf.py` (absolute paths) → binaries in `out/*.sb.bin`.
- Decoded headers/sections into `out/ingested.json` using `profile_ingestion.py` (modern-heuristic variant).
- Runtime probes: now running via `sandbox_runner`/`sandbox_reader`. allow_all runs (OS perms still deny `/etc/hosts` write); deny_all/deny_except_tmp align through runtime-checks. `metafilter_any` now passes (allow foo/bar, deny other) after adding `/private/tmp` literals and using reader to avoid exec overhead.
- Wrapper available: runtime-checks harness can exercise these compiled blobs via `book/api/SBPL-wrapper/wrapper --blob`; reuse that path for future triple captures instead of relying on `sandbox-exec`.
