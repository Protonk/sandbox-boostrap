# Vocab from Cache – Notes

Use this file for dated, concise notes on progress, issues, and commands used. Keep it terse and focused on reproducibility.

## 2025-12-02

- Located dyld shared cache on Sonoma (arm64e) at `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e` (compat path under `/System/Library/dyld` absent).
- `dsc_extractor.bundle` present at `/usr/lib/dsc_extractor.bundle`.
- Added `extract_dsc.swift` shim (uses `dyld_shared_cache_extract_dylibs_progress` from the bundle) and compiled it with `xcrun swiftc -module-cache-path .swift-module-cache -o extract_dsc`.
- Ran extraction: `extract_dsc /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e book/experiments/vocab-from-cache/extracted`. Output includes:
  - `usr/lib/libsandbox.1.dylib`
  - `usr/lib/system/libsystem_sandbox.dylib`
  - `System/Library/PrivateFrameworks/AppSandbox.framework/Versions/A/AppSandbox`
- Initial string scan of `libsandbox.1.dylib` shows contiguous operation-like names starting at offset ~0x3f0c0 (`appleevent-send`, `device*`, `file-read*`, …) through `default-message-filter`, total ~190 strings; `op_count` from canonical blobs is 167, so further alignment/filtering is needed to map names→IDs cleanly.

## 2025-12-03

- Added `harvest_ops.py` to decode `_operation_names` directly from the extracted `libsandbox.1.dylib` (via `nm` + `otool -l`). It masks pointer-auth bits, adds the shared-cache base (0x180000000), and walks `__TEXT.__cstring`.
- Harvest output: `out/operation_names.json` with 196 ordered entries; first entries are `default`, `appleevent-send`, `authorization-right-obtain`, last entries `default-message-filter`, `iokit-async-external-method`, …, `xpc-message-send`.
- The count (196) comes from the span between `_operation_names` and `_operation_info`; earlier 167-op counts were heuristic/decoder artifacts.
- Spot-check: treating op_table length as 196 for compiled SBPLs (e.g., `v1_read`, `v3_mach`) yields sensible nonzero entries at expected IDs (file-read* → index 21, mach-lookup → index 96), confirming the 196-entry vocabulary aligns with compiled blobs.
- Added `harvest_filters.py` to parse `_filter_info` and recover the Filter Vocabulary (masked pointers → `__TEXT.__cstring`). Harvest output: `out/filter_names.json` with 93 entries, first `path`, last `kas-info-selector`. Updated `validation/out/vocab/filters.json` to `status: ok` with these IDs.
