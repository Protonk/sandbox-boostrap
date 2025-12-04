# Vocab from Cache – Notes

Use this file for concise notes on progress, issues, and commands used. Keep it terse and focused on reproducibility.

## Initial cache extraction

- Located dyld shared cache on Sonoma (arm64e) at `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e` (compat path under `/System/Library/dyld` absent).
- `dsc_extractor.bundle` present at `/usr/lib/dsc_extractor.bundle`.
- Added `extract_dsc.swift` shim (uses `dyld_shared_cache_extract_dylibs_progress` from the bundle) and compiled it with `xcrun swiftc -module-cache-path .swift-module-cache -o extract_dsc`.
- Ran extraction: `extract_dsc /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e book/experiments/vocab-from-cache/extracted`. Output includes:
  - `usr/lib/libsandbox.1.dylib`
  - `usr/lib/system/libsystem_sandbox.dylib`
  - `System/Library/PrivateFrameworks/AppSandbox.framework/Versions/A/AppSandbox`
- Initial string scan of `libsandbox.1.dylib` shows contiguous operation-like names starting at offset ~0x3f0c0 (`appleevent-send`, `device*`, `file-read*`, …) through `default-message-filter`, total ~190 strings; `op_count` from canonical blobs is 167, so further alignment/filtering is needed to map names→IDs cleanly.

## Operation names harvest

- Added `harvest_ops.py` to decode `_operation_names` directly from the extracted `libsandbox.1.dylib` (via `nm` + `otool -l`). It masks pointer-auth bits, adds the shared-cache base (0x180000000), and walks `__TEXT.__cstring`.
- Harvest output: `out/operation_names.json` with 196 ordered entries; first entries are `default`, `appleevent-send`, `authorization-right-obtain`, last entries `default-message-filter`, `iokit-async-external-method`, …, `xpc-message-send`.
- The count (196) comes from the span between `_operation_names` and `_operation_info`; earlier 167-op counts were heuristic/decoder artifacts.
- Spot-check: treating op_table length as 196 for compiled SBPLs (e.g., `v1_read`, `v3_mach`) yields sensible nonzero entries at expected IDs (file-read* → index 21, mach-lookup → index 96), confirming the 196-entry vocabulary aligns with compiled blobs.
- Added `harvest_filters.py` to parse `_filter_info` and recover the Filter Vocabulary (masked pointers → `__TEXT.__cstring`). Harvest output: `out/filter_names.json` with 93 entries, first `path`, last `kas-info-selector`. Updated `graph/mappings/vocab/filters.json` to `status: ok` with these IDs.

## Filter names harvest

- Added `check_vocab.py`, a lightweight guardrail that asserts `ops.json`/`filters.json` are `status: ok` with counts ops=196, filters=93. Intended to catch regressions if vocab artifacts drift.

## Cleanup and completion

- Marked experiment complete and deleted the raw cache extraction at `book/experiments/vocab-from-cache/extracted` to reclaim space; retained trimmed libs at `book/graph/mappings/dyld-libs/` for future harvest reruns.

## Cross-checks against public headers/clients (provisional)

- Verified OSS operation coverage: common names used in launchd/WebKit/Chromium/Darling/etc. are present with expected IDs (e.g., `mach-lookup` 96, `file-read*` 21, `file-write*` 29, `file-mount` 19, `job-creation` 85, `appleevent-send` 1, `xpc-message-send` 195). Naming deltas only: `device*`/`device-camera`/`device-microphone` cover “device-config”; `iokit-open*`/`iokit-open-user-client`/`iokit-open-service` cover “iokit-open”; there is no separate `xpc-service` op entry. Total ops=196 as harvested.
- Filter IDs align with the public `sandbox_filter_type` enum and SANDBOX_CHECK flags: `path` id 0, `xattr` id 2, `global-name` id 5, `local-name` id 6, `device-major`/`device-minor` ids 19/20, `appleevent-destination` id 24, `right-name` id 26, `xpc-service-name` id 49, `sysctl-name` id 37. Naming deltas only: `iokit-user-client-type` in place of “class”, `ioctl-command` covers file-ioctl, `nvram-variable` covers nvram name. Total filters=93 as harvested.
- External hook count (Worm’s Look macOS 14.6.1) cites ~159 MACF hooks; our 196-entry userland list should be treated as a superset (MACF-backed + userland/meta ops). No contradiction found; MACF subset classification remains future work.
