# Kernel Symbols – Research Report

## Purpose
Track kernel symbol and string extraction runs for the 14.4.1-23E224 kernelcache and related builds, with a focus on sandbox/AppleMatch/mac_policy anchors that could support later PolicyGraph dispatcher searches. Keep outputs organized so other experiments can reuse them without re-running Ghidra.

## Baseline & scope
- Host/build: Sonoma baseline from `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5` (14.4.1-23E224 kernelcache, arm64).
- Outputs live under `out/<build>/kernel-symbols/` for reuse and comparison across runs.

## Deliverables / expected outcomes
- Per-build symbol and string dumps under `out/<build>/kernel-symbols/` (for example `out/14.4.1-23E224/kernel-symbols/strings.json` and `symbols.json`).
- String-reference scans for sandbox/AppleMatch/mac_policy terms under `out/<build>/kernel-string-refs/`.
- Pointer-table candidate listings (e.g., `out/14.4.1-23E224/op_table_candidates.json`) to support op-table and dispatcher work.
- Notes/Report entries that summarize notable hits and dead ends for later kernel experiments.

## Plan & execution log
### Completed
- Kernel symbol and string extraction completed for the 14.4.1-23E224 kernelcache; outputs recorded under `out/14.4.1-23E224/` (see Appendix “Current state” for detailed counts and paths).
- Initial data-define and string-reference passes run for key sandbox/AppleMatch addresses, with callers/xrefs captured in `data_refs.json` and `kernel-string-refs` outputs where available.
- An op-table candidate sweep produced `out/14.4.1-23E224/op_table_candidates.json` for later correlation with other experiments.

### Maintenance / rerun plan
If new dispatcher hypotheses appear or the kernelcache changes, reuse this outline:

1. **Scope and setup**
   - Confirm the target build ID and baseline in `book/world/.../world.json`, this Report, and `Notes.md`.
   - Decide which additional addresses (strings or symbols) should be included in string-ref and data-define runs.
2. **Symbol/string extraction**
   - Regenerate `kernel-symbols/strings.json` and `symbols.json` under `out/<build>/kernel-symbols/` if needed.
   - Run string-reference scans for sandbox/AppleMatch/mac_policy terms and write results under `out/<build>/kernel-string-refs/`.
3. **Pointer-table and data-define passes**
   - Refresh op-table candidates (`op_table_candidates.json`) when op-table mapping work evolves.
   - Run targeted data-define and xref collection on promising addresses and update `data_refs.json` for downstream experiments.

## Evidence & artifacts
- `out/14.4.1-23E224/kernel-symbols/strings.json` and `symbols.json` with raw string and symbol inventories.
- `out/14.4.1-23E224/kernel-string-refs/string_references.json` from `kernel_string_refs.py` runs.
- `out/14.4.1-23E224/op_table_candidates.json` capturing pointer-table candidates.
- `data_refs.json` outputs from `kernel_data_define_and_refs.py` via `kernel-data-define` wrapper.

## Blockers / risks
- Many sandbox/AppleMatch-related strings and candidate tables currently have zero recorded callers/xrefs under the analyzed configuration, so their connection to the real dispatcher remains speculative.
- Some automated scans treated this KC as x86 instead of ARM64, which can hide real references; future runs need to ensure ARM64 analyzers are active when interpreting pointer and immediate patterns.

## Next steps
- Follow the “Next pivots” in the Appendix: targeted data-define runs on candidate addresses, and, when available, coordination with mac_policy_ops/dispatcher searches in the `symbol-search` experiment.

## Appendix
### Current state
- Latest run (Dec 2 2025) completed in ~69s with ARM64 analyzers only; outputs at `out/14.4.1-23E224/kernel-symbols/`.
- `strings.json`: ~243k entries; ~205 entries contain sandbox/AppleMatch/mac_policy terms (addresses include `0x-7fffdf10f0` `com.apple.security.sandbox`, `0x-7fffdf3a68` `com.apple.kext.AppleMatch`).
- `symbols.json`: ~215 entries emitted by the `kernel_symbols.py` script.
- Initial data-define pass (no analysis, process-existing) on `0x-7fffdf10f0` (`com.apple.security.sandbox` TEXT) yielded a defined string with zero callers in `data_refs.json` (as expected without full analysis).
- Batch data-define (no analysis) across 11 sandbox/mac_policy targets: all defined, zero callers (LINKEDIT symbols remain null type/value).
- Track B comparison: re-ran `addr:0xffffff800020ef10` with analysis; still zero callers. Analysis completed ~59s with only ARM64 analyzers; no xrefs surfaced.
- String-refs pass (Dec 2): `kernel_string_refs.py` via `run_task.py kernel-string-refs --process-existing --exec` found three string hits (same sandbox/AppleMatch literals), zero symbol hits, zero external-library matches; references lists were empty. Output stored at `out/14.4.1-23E224/kernel-string-refs/string_references.json`.
- String-refs broadened sweep (Dec 3, no-analysis, process-existing): 918 string hits, 0 symbol hits, 0 externals with queries spanning sandbox/mac_policy/seatbelt substrings and AppleMatch/sandbox strings. Notable hits include `0x-7fffdf3a68 com.apple.kext.AppleMatch`, `0x-7fffdf10f0 com.apple.security.sandbox`, `0x-7ffe53900e com.apple.security.app-sandbox`, plus generic “sandbox”/dyldPolicy strings. Output mirrored into `out/14.4.1-23E224/kernel-string-refs/string_references.json`.
- Data-define reruns (Dec 3) on unsigned forms `addr:0xffffff800020ef10`, `addr:0xffffff800020c598`, `addr:0xffffff8002dd2920` with `--process-existing --no-analysis`; each processed 1 target, latest `data_refs.json` shows `com.apple.security.sandbox` at `0x-7ffd22d6e0` with no callers (overwrites per run).
- Op-table refresh (Dec 3, no-analysis, process-existing): 33 pointer-table candidates regenerated; output mirrored to `out/14.4.1-23E224/op_table_candidates.json` for comparison with symbol/string pivots.

### Next pivots
- Run `run_data_define.py` with `--process-existing --no-analysis` on key addresses (e.g., `0x-7fffdf10f0`, `0x-7fffdf3a68`, selected `_sandbox_*` symbols) to gather xrefs/callers.
- Use `run_task.py kernel-op-table --process-existing` if op-table mapping is needed alongside symbols.
- Keep analyzer runs under ARM64 defaults; only rerun full analysis if new pre-scripts or processor IDs change.
