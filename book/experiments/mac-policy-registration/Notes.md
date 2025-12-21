# mac-policy-registration – Notes

- Use this log for commands, observations, and candidate structs/registration sites as they are discovered.
- Keep references repo-relative; avoid timestamps.

## Setup and first scan attempts

- Added Ghidra script `sandbox_kext_conf_scan.py` and scaffold task `sandbox-kext-conf-scan` (import target `sandbox_kext` -> `dumps/Sandbox-private/14.4.1-23E224/kernel/sandbox_kext.bin`). Heuristic slots: name/fullname/labelnames/count/ops/flags/field/runtime_flags.
- First headless attempt (`python -m book.api.ghidra.run_task sandbox-kext-conf-scan --project-name sandbox_kext_14.4.1-23E224 --no-analysis --exec`) failed to import `sandbox_kext.bin` (IndexOutOfBoundsException during Mach-O load). Placeholder `mac_policy_conf_candidates.json` written with `candidate_count: 0` until kext import path is fixed.

## Rebuild from BootKernelCollection (arm64e)

- Added `rebuild_sandbox_kext.py` to reconstruct the sandbox fileset entry from `BootKernelCollection.kc` (LC_FILESET_ENTRY `com.apple.security.sandbox`). The helper slices the full range (base 0x91fd20 → end 0x63687b7), rewrites load-command offsets relative to base, and overwrites `dumps/Sandbox-private/14.4.1-23E224/kernel/sandbox_kext.bin` (now ~90 MB, `file` reports arm64e).
- Reran `python -m book.api.ghidra.run_task sandbox-kext-conf-scan --project-name sandbox_kext_14.4.1-23E224 --no-analysis --exec` against the rebuilt binary. Import succeeded; `mac_policy_conf_candidates.json` refreshed with `candidate_count: 0` (no hits under the current heuristics). Guarded `_read_ascii` to skip invalid pointers after the first MemoryAccessException during scanning.

## Relaxed scan (minimal hard checks, offline ranking)

- Scanner now separates hard vs soft checks (hard: data/const range, readable slots, aligned pointers within image or NULL, `labelname_count` <= 32; soft: printable strings, ops present, loadtime flag hints). Captures two extra slots for optional list/data pointers and emits `soft_score/soft_flags`.
- Reran `python -m book.api.ghidra.run_task sandbox-kext-conf-scan --project-name sandbox_kext_14.4.1-23E224 --no-analysis --exec`; output `mac_policy_conf_candidates.json` reports `candidate_count: 82`, `probe_points: 16495`, `bytes_scanned: 132195`, `scan_slots: 10`. All candidates currently have NULL name/fullname/labelnames/ops pointers (only flag fields vary).
- Added offline filter `filter_conf_candidates.py` to rank candidates; first pass writes `mac_policy_conf_candidates_ranked.json` (still dominated by zeroed structs; no string/ops hints yet).

## Enumerate sandbox-like fileset entries + pointer-range-relaxed calibration

- `rebuild_sandbox_kext.py --all-matching` now lists/rebuilds LC_FILESET_ENTRY names containing sandbox/seatbelt. For this world, only `com.apple.security.sandbox` is present; rebuilt copy stored as `sandbox_kext_com_apple_security_sandbox.bin` (canonical still `sandbox_kext.bin`).
- Calibration pass dropping the “pointer must be inside image” constraint: `python -m book.api.ghidra.run_task sandbox-kext-conf-scan --project-name sandbox_kext_14.4.1-23E224-anyptr --no-analysis --exec --script-args any-ptr`.
  - Output (`allow_any_ptr: true`): `candidate_count: 118`, `probe_points: 16495`, `bytes_scanned: 132195`.
  - 36/118 candidates have any non-zero pointer-like slot; none resolve to printable strings (name/fullname stay NULL).
  - Representative slots (hex; flag-only/PAC-looking, not plausible mac_policy_conf):
    - `0x-1fff7b37540` (ranked top): name/fullname/labelnames=NULL, `labelname_count=0`, `ops=0x8020438d044067b8`, `field/label=0x8180158604406728`, `loadtime_flags=0`, `runtime_flags=0`.
    - `0x-1fff7b36f40`: name/fullname/labelnames=NULL, `ops=0x80101586043fff58`, `field/label=0x80501586043ffe38`, `loadtime_flags=0x43ffec8`, `runtime_flags=0`.
    - `0x-1fff7b34130`: all pointer slots 0 except `extra1=0x20`, flags 0.
    - `0x-1fff7b36a98`: all pointers 0, `runtime_flags=0x93dd5e`.
  - Pattern: even with unconstrained pointer ranges, no printable strings and no obvious ops/labelnames; values look like PAC’d or unrelated constants, not a populated mac_policy_conf. These snapshots are anchors supporting the ok-negative claim in Report.md, not candidates to pursue.

## Registration-site recovery (symbol + GOT pivots)

- Added `mac_policy_register_scan.py` plus scaffold tasks `kernel-mac-policy-register` (BootKernelCollection) and `sandbox-kext-mac-policy-register` (sandbox kext) to search for mac_policy_register call sites with light arg recovery.
- `python3 book/api/ghidra/run_task.py sandbox-kext-mac-policy-register --process-existing --project-name sandbox_kext_14.4.1-23E224 --exec --script-args flow` reports `target_count: 4` (external `_mac_policy_register` + `_amfi_register_mac_policy`) but `call_site_count: 0` (`dumps/ghidra/out/14.4.1-23E224/sandbox-kext-mac-policy-register/registration_sites.json`).
- `python3 book/api/ghidra/run_task.py kernel-mac-policy-register --process-existing --project-name sandbox_14.4.1-23E224_kc --no-analysis --exec` reports `target_count: 0`, `call_site_count: 0` (no mac_policy symbol names in BootKernelCollection).
- `otool -Iv dumps/Sandbox-private/14.4.1-23E224/kernel/sandbox_kext.bin` shows `__DATA_CONST,__auth_got` entries for `_amfi_register_mac_policy` (`0xfffffe00084c7ea8`) and `_mac_policy_register` (`0xfffffe00084c80a0`); full output saved to `book/experiments/mac-policy-registration/out/otool_indirect_symbols.txt`.
- Added `kernel_adrp_ldr_scan.py` and sandbox-kext variants of ADRP scans/data-define; ran:
  - `python3 book/api/ghidra/run_task.py sandbox-kext-adrp-add-scan --process-existing --project-name sandbox_kext_14.4.1-23E224 --exec --script-args 0xfffffe00084c80a0 all` → `0` matches.
  - `python3 book/api/ghidra/run_task.py sandbox-kext-adrp-ldr-scan --process-existing --project-name sandbox_kext_14.4.1-23E224 --exec --script-args 0xfffffe00084c80a0 all` → `0` matches.
  - `python3 book/api/ghidra/run_task.py sandbox-kext-data-define --process-existing --project-name sandbox_kext_14.4.1-23E224 --exec --script-args addr:0xfffffe00084c80a0 addr:0xfffffe00084c7ea8` → data values recorded but no callers (`dumps/ghidra/out/14.4.1-23E224/sandbox-kext-data-define/data_refs.json`).

- Extended `mac_policy_register_scan.py` to scan authenticated GOT for indirect BLR/BLRAA call sites and dump the `__auth_got` table.
- `python3 book/api/ghidra/run_task.py sandbox-kext-mac-policy-register --process-existing --project-name sandbox_kext_14.4.1-23E224 --exec --script-args flow indirect`:
  - `indirect_call_sites: 0` and `call_site_count: 0` (no mac_policy call sites found).
  - `got_entries` captured for `__auth_got` with pointer values but no symbol names (`registration_sites.json`).
- Added `sandbox-kext-adrp-ldr-got-scan` for ADRP+LDR hits into `__auth_got`; ran:
  - `python3 book/api/ghidra/run_task.py sandbox-kext-adrp-ldr-got-scan --process-existing --project-name sandbox_kext_14.4.1-23E224 --exec --script-args auth_got 32 all` → `0` matches (`dumps/ghidra/out/14.4.1-23E224/sandbox-kext-adrp-ldr-got-scan/adrp_ldr_scan.json`).
- Normalized address values to signed 64-bit when calling `toAddr` in `kernel_adrp_ldr_scan.py`; reran `sandbox-kext-adrp-ldr-got-scan` with `auth_got 32 all` and still saw `0` matches (`adrp_seen: 3452`, `ldr_literal_seen: 0`, `truncated_bases: 1508`, `got_block_mode: auth_got`).
- Reran `sandbox-kext-mac-policy-register` with `flow indirect-all all`: `target_count: 4`, `call_site_count: 0`, `indirect_call_sites: 0`, `got_block_mode: auth_got+auth_ptr+got`, `got_entries: 332`.

## Stub + GOT join attempt

- Block disasm sweep for "stub" matched zero blocks; sandbox kext block names do not include `stub`. Reran with `text` to cover `__text` (`sandbox-kext-block-disasm`), scanning one executable block (`dumps/ghidra/out/14.4.1-23E224/sandbox-kext-block-disasm/disasm_report.json`).
- Added `kernel_stub_got_map.py` and task `sandbox-kext-stub-got-map` to map ADRP+LDR stub sequences to GOT entries; run over `text` blocks with lookahead 6 yields `0` matches (`adrp_seen: 3648`, `match_count: 0`).
- Joined stub map with `otool -Iv` indirect symbols via `match_stub_got.py`; `stub_targets.json` reports `match_count: 0`, `target_count: 0`.
- Reran `sandbox-kext-mac-policy-register` with `stub-targets=.../stub_targets.json` plus `flow indirect-all all`; still `call_site_count: 0`, `stub_target_count: 0`.
- Extended `kernel_stub_got_map.py` with BLR/BR backtracking (register dataflow + MOV alias); reran `sandbox-kext-stub-got-map` over all exec blocks with `lookahead 16`:
  - `branch_seen: 647`, `branch_hits: 0`, `adrp_seen: 3648`, `match_count: 0`.
  - `stub_got_map.json` still empty; `stub_targets.json` still `target_count: 0`.
- `match_stub_got.py` needs `PYTHONPATH=$PWD`; a first run without PYTHONPATH raised `ModuleNotFoundError: book`, then reran successfully.
- `mac_policy_register_scan.py` now normalizes signed addresses and follows MOV/MOVK aliasing in `_resolve_reg_value`; reran `sandbox-kext-mac-policy-register` with stub targets and still `call_site_count: 0`, `indirect_call_sites: 0`.
- Ran `sandbox-kext-arm-const-base-scan` over `__auth_got` range (`0x-1fff7b382e0` → `0x-1fff7b37981`) with `lookahead 16 all`: `adrp_seen: 0`, `matches add:0 ldr:0` (`arm_const_base_scan.json`).
- Added `kernel_got_ref_sweep.py` + task `sandbox-kext-got-ref-sweep`; ran with `with_refs_only=1` and then full `all`:
  - `got_ref_sweep.json`: `entries=332`, `with_refs=32`, `got_block_mode=auth_got+auth_ptr+got`.
  - auth_got entries for `_mac_policy_register` (`0x-1fff7b38158`) and `_amfi_register_mac_policy` (`0x-1fff7b38250`) have `ref_count: 0` (no callers).
- Added `kernel_got_load_sweep.py` + task `sandbox-kext-got-load-sweep` to scan code for GOT loads.
  - Track A (refs-only, target_only set): `hits=0` (`ref_hits: 0`, `literal_hits: 0`, `computed_hits: 0`) for the target auth_got entries.
  - Track B (lookback 32, target_only set): still `hits=0` across 65,548 instructions scanned (`got_load_sweep.json`).
- Full sweep (no target_only filter) yields `total_hits: 766` (all direct refs; `computed_hits: 0`, `literal_hits: 0`), almost entirely in `__got` (`__got: 765`, `__auth_ptr: 1`, `__auth_got: 0`).

## AMFI pivot (AppleMobileFileIntegrity)

- Listed LC_FILESET_ENTRY names with `PYTHONPATH=$PWD python3 book/experiments/mac-policy-registration/rebuild_sandbox_kext.py --list`; AMFI is `com.apple.driver.AppleMobileFileIntegrity` (offset `0x48d3f0`). First rebuild attempt used the offset (`--entry-id 0x48d3f0`) and failed because `--entry-id` expects the entry name, not the offset.
- Rebuilt AMFI slice: `PYTHONPATH=$PWD python3 book/experiments/mac-policy-registration/rebuild_sandbox_kext.py --entry-id com.apple.driver.AppleMobileFileIntegrity`, output `dumps/Sandbox-private/14.4.1-23E224/kernel/sandbox_kext_com_apple_driver_AppleMobileFileIntegrity.bin`.
- Imported AMFI into `amfi_kext_14.4.1-23E224` via `amfi-kext-block-disasm` (`text 4 0 1`); disasm report shows 1 executable block (`dumps/ghidra/out/14.4.1-23E224/amfi-kext-block-disasm/disasm_report.json`).
- `amfi-kext-mac-policy-register` with `flow indirect-all all` wrote `registration_sites.json` with `target_count: 6`, `call_site_count: 0`, `indirect_call_sites: 0`; targets include `_mac_policy_register`, `_amfi_register_mac_policy`, and `__ZL15_policy_initbsdP15mac_policy_conf`.
- `otool -Iv` on AMFI saved to `book/experiments/mac-policy-registration/out/otool_indirect_symbols_amfi.txt`; `_mac_policy_register` entry at `0xfffffe0007e5c290` (signed `0x-1fff81a3d70`) in `__auth_got`.
- `amfi-kext-got-ref-sweep`: `entries=329`, `with_refs=47`; `_mac_policy_register` GOT entry has `ref_count: 0`.
- `amfi-kext-got-load-sweep` target-only (`target_only=0x-1fff81a3d70`) returns `hits: 0`; full sweep returns `hits: 314` with counts `__got: 300`, `__auth_ptr: 14`, `__auth_got: 0`.

## AMFI function dump + KC pivots

- Added `amfi-kext-function-dump` task and ran:
  - `python3 book/api/ghidra/run_task.py amfi-kext-function-dump --process-existing --project-name amfi_kext_14.4.1-23E224 --no-analysis --exec --script-args _amfi_register_mac_policy __ZL15_policy_initbsdP15mac_policy_conf`
  - Output `function_dump.json` shows `_amfi_register_mac_policy` contains no `mac_policy_register` call; `__ZL15_policy_initbsdP15mac_policy_conf` was not found as a function.
- First attempt to use `kernel-string-refs` with `--process-existing --project-name sandbox_14.4.1-23E224_kc` failed (`Requested project program file(s) not found: BootKernelExtensions.kc`); the KC project contains `BootKernelCollection.kc`, not the extensions slice.
- Imported BootKernelExtensions into `sandbox_14.4.1-23E224_extensions` and reran:
  - `python3 book/api/ghidra/run_task.py kernel-string-refs --project-name sandbox_14.4.1-23E224_extensions --exec --script-args all mac_policy mac_policy_register mac_policy_conf policy_initbsd AppleMobileFileIntegrity amfi sandbox seatbelt`
  - Result: `string_hits: 433`, but mac_policy-related hits resolve to `__LINKEDIT` data refs only (no executable references in `string_references.json`).
  - Ghidra analysis logged pcode errors during BootKernelExtensions import, but the run completed and wrote output.
- `kernel-imports` on BootKernelExtensions with substrings (`mac_policy`, `amfi`, `sandbox`, `seatbelt`, `AppleMobileFileIntegrity`) returned `symbol_count: 0` (`external_symbols.json`).
- `kernel-collection-imports` on BootKernelCollection with the same substrings returned `symbol_count: 0`.
- KC constant scans (BootKernelExtensions project):
  - `kernel-adrp-add-scan` for `-0x1fff819a290` (`__ZL10mac_policy` in AMFI) -> `0` matches (`adrp_seen: 60`).
  - `kernel-adrp-ldr-scan` for `-0x1fff81a3d70` (AMFI `_mac_policy_register` auth_got) -> `0` matches (`adrp_seen: 60`).
  - `kernel-imm-search` for `0xfffffe0007e5c290` -> `0` hits.
