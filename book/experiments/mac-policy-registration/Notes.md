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

## KC stub/trampoline sweep (auth-stub pivot)

- Added `kernel_stub_call_sites.py` and scaffold tasks `kernel-collection-stub-got-map` + `kernel-collection-stub-call-sites` to scan direct BL/B call sites into stub/trampoline ranges.
- First `kernel-collection-stub-got-map` attempt failed using the default project (`sandbox_14.4.1-23E224`); BootKernelCollection.kc is only in `sandbox_14.4.1-23E224_kc`.
- Reran with `--project-name sandbox_14.4.1-23E224_kc` and `block_substr=stub` (exec-only): `match_count: 0`, `adrp_seen: 30`, `block_filter: __stubs`, `got_block_mode: auth_got+auth_ptr+got`.
- Attempted full exec-block sweep (`scan_all`) with default harness timeout; the run timed out. Reran with `--timeout 600` and completed: `match_count: 0`, `adrp_seen: 718925`, `scan_all_blocks: true`.
- `otool -Iv` on BootKernelCollection emits only the file header line (no `Indirect symbols` table); saved to `book/experiments/mac-policy-registration/out/otool_indirect_symbols_kc.txt`.
- `match_stub_got.py` against the KC stub map + `otool` output yields `stub_targets_kc.json` with `stub_count: 0`, `match_count: 0`, `target_count: 0`.
- `kernel-collection-stub-call-sites` with `stub_targets_kc.json` reports `call_site_count: 0` (`stub_call_sites.json`).

## KC truth layer (fileset + chained fixups)

- First run of `kc_truth_layer.py` failed without `PYTHONPATH=$PWD` (`ModuleNotFoundError: No module named 'book'`); reran with PYTHONPATH and completed.
- `kc_truth_layer.py` emits:
  - `kc_fileset_index.json`: BootKernelCollection is `MH_FILESET` with 355 fileset entries and 7 top-level segments.
  - `kc_fixups_summary.json` + `kc_fixups.jsonl`: top-level `LC_DYLD_CHAINED_FIXUPS` parsed (`fixups_version: 0`, `imports_count: 0`), pointer_format `8` only.
  - Fixup counts: `total_fixups: 323` (`__DATA_CONST: 202`, `__DATA: 121`).
  - Decode assumptions (under exploration): pointer_format 8 uses `target` (low 30 bits), `cache_level` (bits 30–31), `next_delta` (bits 32–43, scaled by 4). Base guess derived from the minimum KC segment vmaddr.

## String-anchored mac_policy_register call-site hunt (KC)

- Added `kernel_string_call_sites.py` + task `kernel-collection-string-call-sites`. First run crashed with a null address when parsing function entry addresses; fixed by parsing hex to signed addresses and reran successfully.
- Ran `kernel-collection-string-call-sites` with query strings `Security policy loaded` and `mac_policy_register failed`:
  - `string_hit_count: 4`, `function_hit_count: 4`, `call_site_count: 53`.
  - Candidate function referencing `Security policy loaded: %s (%s)\n`: `FUN_fffffe0008d64498` (entry `0x-1fff729bb68`).
  - 7 call sites to that function recorded in `string_call_sites.json`.
- Added `derive_mac_policy_call_sites.py` to filter call sites for the `Security policy loaded` function and map them to fileset entries using `kc_fileset_index.json`.
  - Output `mac_policy_register_call_sites.json` records 7 call sites; all map to `com.apple.driver.AppleTrustedAccessory`.

## mac_policy_register instances (KC dataflow)

- Extended `kernel_mac_policy_register_instances.py`:
  - decompiler-based argument recovery (PcodeOp-based varnode evaluation),
  - fixups lookup keyed by unsigned vmaddr,
  - stack-slot backtrack for LDR/LDUR/LDP from `sp`/`x29`,
  - `mpc_block` + `mpc_fileset_entry` + `mpc_ops_fileset_entry` fields in output,
  - `arg_resolution` captures per-call-site resolution attempts.
- Ran:
  - `PYTHONPATH=$PWD python3 book/api/ghidra/run_task.py kernel-mac-policy-register-instances --build 14.4.1-23E224 --project-name sandbox_14.4.1-23E224_kc --process-existing --no-analysis --exec --script-args call-sites=book/experiments/mac-policy-registration/out/mac_policy_register_call_sites.json fixups=book/experiments/mac-policy-registration/out/kc_fixups.jsonl fileset-index=book/experiments/mac-policy-registration/out/kc_fileset_index.json mac-policy-register=0x-1fff729bb68 max-back=200`
  - Output: `dumps/ghidra/out/14.4.1-23E224/kernel-mac-policy-register-instances/mac_policy_register_instances.json`.
- Results: 7 call sites, 4 resolved names from decoded `mac_policy_conf` (`AppleImage4`, `Quarantine`, `EndpointSecurity`, `Sandbox`). All resolved structs/ops pointers map to `com.apple.driver.AppleTrustedAccessory`.
- Unresolved cases:
  - One call site resolves `x0 = x19 + 0xb10` with unresolved base (mpc_addr `0xb10`).
  - One `mpc_addr` in `__const` with zeroed fields (name/fullname/ops raw 0).
  - One `mpc_addr` in `__bss` with zeroed fields (likely runtime-initialized).

## mac_policy_register instances (field-write reconstruction)

- Extended `kernel_mac_policy_register_instances.py` with field-write reconstruction:
  - backtracks STR/STP stores into `mpc_name`, `mpc_fullname`, `mpc_ops` slots (offsets 0x0/0x8/0x20),
  - handles ADRP immediates as scalars for address recovery,
  - improves stack-slot recovery for `ldp/str` pairs,
  - adds `mpc_reconstructed` (base + per-field store evidence).
- Added ops-offset inference in `mac_policy_register` (pcode + listing fallback); discovered `mpo_policy_init` offsets `0x398` and `0x3a0`.
- Reran `kernel-mac-policy-register-instances` (same command as above).
- Results after reconstruction:
  - Newly recovered policy identities for the 3 formerly-unresolved call sites:
    - `ASP` / `Apple System Policy` (from stores to `x19 + 0xb10/+0xb18`)
    - `mcxalr` / `MCX App Launch` (from stores near the `__bss` conf)
    - `Apple Mobile File Integrity` (fullname; `mpc_name` still unresolved via stack slot)
  - `mpo_policy_init` offsets now populated; resolved init pointers for `Sandbox` and `Quarantine` (owner entry `com.apple.driver.AppleTrustedAccessory`), while other policies have NULL init pointers (raw 0) or unresolved ops pointers.

## mac_policy_register instances (ops-owner attribution + remaining gaps)

- Updated `kernel_mac_policy_register_instances.py`:
  - pair-aware `LDP` offset handling and function-boundary limiting for register backtracking,
  - call-site argument recovery now respects function bodies (avoid crossing into unrelated code),
  - ops-owner sampling (`ops_owner_histogram` + `mpc_ops_owner`) emits the dominant fileset entry from ops-table pointers,
  - call-chain fallback for ops pointer resolution (caller arg recovery + data-ref scan around indirect init tables).
- Reran `kernel-mac-policy-register-instances` with the same command (output refreshed in `dumps/ghidra/out/14.4.1-23E224/kernel-mac-policy-register-instances/mac_policy_register_instances.json`).
- `kernel-collection-function-dump` runs:
  - `0xfffffe0009df4188` + `0xfffffe0009df43bc` to inspect the ASP registration chain.
  - `0xfffffe0009af0930` to confirm AMFI store sequence (`stp x19,x9,[x0]` with `x0` materialized via ADRP+ADD).
- `kernel-collection-function-info` shows `FUN_fffffe0009df43bc` has only a DATA ref from `0x-1fff80ded88` (no direct callers); `FUN_fffffe0009df4188` is called from `0x-1fff620bc28`.
- AMFI `mpc_name` now resolves to `"AMFI"` via dominant stores (string fallback still used in the store trace).
- ASP `mpc_ops` remains unresolved: x0 is passed through an indirect init entry and data-ref scans near `0x-1fff80ded88` surface only `__text` pointers (no writable base pointer to anchor x0), so ops pointer remains runtime-only.
  - The reconstruction now records a symbolic ops expression (`x0 + 0x98`) plus `relative_to_mpc_base = -0xa78` for the ASP case.

## KC fixups re-walk + ops attribution (fixups/PAC correctness)

- Re-ran `kc_truth_layer.py` with full chain walking (next*4) and base_pointers:
  - Fixups count now 4,319 (up from 323) across `__DATA_CONST` and `__DATA`; per-page coverage and max chain length recorded in `kc_fixups_summary.json`.
  - Base pointer is set for cache_level 0 (min KC vmaddr); other cache levels remain unknown.
- Re-ran `kernel-mac-policy-register-instances` with the refreshed fixups map.
- Ops-owner sampling now uses fixup-aware + PAC-canonicalized pointer handling; results remain empty for `AMFI` and `mcxalr` ops tables (no executable targets in the first 0x800 bytes).
- ASP ops reconstruction path is implemented but finds no dominating stores into the ops table region (no `x0 + 0x98 + off` stores before the registration call).

## KC fixups inference + ops attribution (base-pointer coverage)

- Extended `kc_truth_layer.py` with a fixups pre-pass and base-pointer inference:
  - cache_level 2 now inherits base pointer 0 via coverage (`2727/2735` fixups resolve into fileset entry ranges; threshold 0.95).
  - cache_level 1/3 remain unresolved (12 fixups each; coverage <= 0.083); `unresolved_unknown_base: 24`.
  - New resolved counts: `resolved_in_entry: 3844`, `resolved_in_exec: 732`, `resolved_outside: 451` (see `kc_fixups_summary.json`).
- Updated `kernel_mac_policy_register_instances.py`:
  - ops-owner scan now stops only after seeing values and scans up to 0x4000 bytes; `ops_slot_dump` uses the same window.
  - AMFI/mcxalr now have non-zero exec-pointer counts in ops histograms; owners still map to `com.apple.driver.AppleTrustedAccessory` for all non-ASP policies.
- Dispatcher-context pass for ASP now uses call-site candidates + table-range filtering; no dispatcher-context matches returned, so ASP `mpc_ops` remains unresolved.

## KC segment-interval attribution + ops recovery refresh

- Generated a full fixups file for audit work: `PYTHONPATH=$PWD python3 book/experiments/mac-policy-registration/kc_truth_layer.py --build-id 14.4.1-23E224 --fixups-mode full --out-dir dumps/Sandbox-oversize/mac-policy-registration` (full records stored outside source control).
- Ran fixups audit using the full file: `PYTHONPATH=$PWD python3 book/experiments/mac-policy-registration/kc_fixups_audit.py --fixups dumps/Sandbox-oversize/mac-policy-registration/kc_fixups.jsonl --fileset-index book/experiments/mac-policy-registration/out/kc_fileset_index.json --summary book/experiments/mac-policy-registration/out/kc_fixups_summary.json --out book/experiments/mac-policy-registration/out/kc_fixups_audit.json` → `cache_level_counts: {0: 914488}`, `next_out_of_page_fraction: {0: 0.0}`.
- Re-ran ASP fixup signature scan with compact fixups (resolved-only): `PYTHONPATH=$PWD python3 book/experiments/mac-policy-registration/asp_conf_fixup_signature_scan.py --fixups book/experiments/mac-policy-registration/out/kc_fixups.jsonl --fileset-index book/experiments/mac-policy-registration/out/kc_fileset_index.json --instances dumps/ghidra/out/14.4.1-23E224/kernel-mac-policy-register-instances/mac_policy_register_instances.json --out book/experiments/mac-policy-registration/out/asp_conf_fixup_candidates.json` → `resolved_candidate_count: 0` and no name/fullname slot matches.
- Re-ran ASP fixup signature scan with full fixups + `--allow-unresolved` to include target-bit matching: `PYTHONPATH=$PWD python3 book/experiments/mac-policy-registration/asp_conf_fixup_signature_scan.py --fixups dumps/Sandbox-oversize/mac-policy-registration/kc_fixups.jsonl --fileset-index book/experiments/mac-policy-registration/out/kc_fileset_index.json --instances dumps/ghidra/out/14.4.1-23E224/kernel-mac-policy-register-instances/mac_policy_register_instances.json --allow-unresolved --out book/experiments/mac-policy-registration/out/asp_conf_fixup_candidates_full.json` → `resolved_candidate_count: 0`, `target_candidate_count: 0`.
- Expanded ASP interprocedural store-chain collection (object-relative writes) in `kernel_mac_policy_register_instances.py`, then reran with compact fixups: `PYTHONPATH=$PWD python3 book/api/ghidra/run_task.py kernel-mac-policy-register-instances --build 14.4.1-23E224 --project-name sandbox_14.4.1-23E224_kc --process-existing --no-analysis --exec --script-args call-sites=book/experiments/mac-policy-registration/out/mac_policy_register_call_sites.json fixups=book/experiments/mac-policy-registration/out/kc_fixups.jsonl fixups-mode=compact fileset-index=book/experiments/mac-policy-registration/out/kc_fileset_index.json mac-policy-register=0x-1fff729bb68 max-back=200`.
- ASP store-chain results: 22 functions scanned (depth <= 3), 22 object-relative stores in the ops/conf windows (12 ops, 10 conf). 9 exec pointer stores in ops region all map to `com.apple.AppleSystemPolicy`, and offsets cluster at `0x98 + {0x30,0x40,0x48,0x58,0x68,0x80,0x90,0x120,0x14c,0x200,0x3a0,0x3d0}` relative to `this` (captured in `asp_store_chain` inside `mac_policy_register_instances.json`).
- Added memcpy/bcopy-style bulk init detection to the ASP store-chain collector (argument-shape based; detects dst in ops/conf window + large length + src pointer or zero fill) and re-ran `kernel-mac-policy-register-instances` with compact fixups. No bulk init calls detected (`bulk_inits: 0`), so the ASP ops map remains derived from direct exec-pointer stores only (`ops_patch_slots: 9`, `ops_template_slots: 0`, `ops_slots_merged: 9`). Run required a longer timeout (initial 120s timeout hit, reran with 180s).
- Added ASP offset cross-check mapping (external) and re-ran the KC pass. ASP `ops_slots_merged` now include `absolute_this_offset` and external hook labels for offsets `{0x128, 0x1b8, 0x298, 0x468}`; matches recorded in `asp_store_chain.offset_crosscheck` with hook names for `file_check_mmap`, `file_check_library_validation`, and `proc_notify_exec_complete` (source: Objective-See writeup). Treat as external/brittle cross-validation.

- `kc_truth_layer.py` now builds a segment-interval map from each fileset entry’s `LC_SEGMENT_64` ranges (address space: KC on-disk vmaddrs, slide=0) and excludes `__LINKEDIT` from attribution.
  - Overlap inspection: all overlaps were identical `__LINKEDIT` ranges shared across entries (354 overlaps); exclusion drops overlap_total to 0.
  - New metadata: 1440 intervals, excluded `__LINKEDIT: 355`, `page_start_mode_counts` shows `multi: 0`, and `resolved_ambiguous: 0`.
  - Resolved counts after inference unchanged: `resolved_in_entry: 3844`, `resolved_in_exec: 3801`, `resolved_outside: 451`, `unresolved_unknown_base: 24` (cache_level 1/3).
- Re-ran `derive_mac_policy_call_sites.py`; the 7 call sites now map to distinct owner entries: `com.apple.security.AppleImage4`, `com.apple.driver.AppleMobileFileIntegrity`, `com.apple.security.quarantine`, `com.apple.AppleSystemPolicy`, `com.apple.iokit.EndpointSecurity`, `com.apple.security.sandbox`, `com.apple.kext.mcx.alr`.
- `kernel_mac_policy_register_instances.py` updates:
  - Derives `mpc_ops_offset = 0x20` and `mpo_policy_init` offsets `0x398/0x3a0` directly from `mac_policy_register`.
  - Always reconstructs name/fullname if missing (even when ops are resolved).
  - Adds global-store fallback for `mpc_ops` when static conf fields are zeroed.
  - Ops-owner sampling window raised to 0x6000 bytes.
- Reran `kernel-mac-policy-register-instances`; all 7 policies now have names/fullnames:
  - `AppleImage4`, `AMFI`, `Quarantine`, `ASP`, `EndpointSecurity`, `Sandbox`, `mcxalr`.
  - Ops owners now map to distinct entries (no AppleTrustedAccessory collapse): AppleImage4 → `com.apple.security.AppleImage4`, Quarantine → `com.apple.security.quarantine`, Sandbox → `com.apple.security.sandbox`, EndpointSecurity → `com.apple.kernel`, AMFI → `com.apple.kernel`, mcxalr → `com.apple.filesystems.msdosfs`.
  - AMFI/mcxalr `mpc_ops` resolved via global-store fallback; ASP still unresolved (no dispatcher-context base recovered, `mpc_ops` remains `x0 + 0x98`).

## ASP dispatcher-context scan (global BLR sweep)

- Expanded dispatcher-context recovery to include read references and a global BLR/BLRA sweep (`_scan_dispatchers_global`, capped backtrace depth to 60); added `source` tags (`table_scan`, `global_scan`) to any dispatcher context hits.
- Fixed `_resolve_reg_value` to avoid `base_val` unbound when resolving LDR chains; reran `kernel-mac-policy-register-instances` (~96s).
- Result: no dispatcher-context matches for ASP; `dispatcher_context` remains empty and `mpc_ops` is still unresolved (`x0 + 0x98`).

## Fixups sanity gate + ASP fixup signature scan

- `kc_truth_layer.py` now emits `sanity` in `kc_fixups_summary.json` and skips base-pointer inference when non-zero cache levels dominate:
  - `cache_level_counts`: `{0: 1560, 1: 12, 2: 2735, 3: 12}`; `cache_nonzero_fraction ≈ 0.639`, so inference is **skipped** (`status: skipped_sanity_gate`).
  - `unresolved_unknown_base_fraction ≈ 0.639` after the gate, reflecting the same cache-level distribution.
- New script `asp_conf_fixup_signature_scan.py` searches fixup slots for adjacent `(mpc_name, mpc_fullname)` pointers (ASP) and derives `mpc_base/x0_base/ops_base` when found.
  - Run: `PYTHONPATH=$PWD python3 book/experiments/mac-policy-registration/asp_conf_fixup_signature_scan.py --fixups book/experiments/mac-policy-registration/out/kc_fixups.jsonl --fileset-index book/experiments/mac-policy-registration/out/kc_fileset_index.json --instances dumps/ghidra/out/14.4.1-23E224/kernel-mac-policy-register-instances/mac_policy_register_instances.json --out book/experiments/mac-policy-registration/out/asp_conf_fixup_candidates.json`
  - Output: `status: no_adjacent_fixup_slots`, `name_ptr_matches: 0`, `fullname_ptr_matches: 0` (no static fixup slots resolved to the ASP strings under the current fixups gate).
  - Re-run with `--allow-unresolved` (target-bit matching): `status.resolved = no_adjacent_fixup_slots`, `status.target = no_adjacent_target_slots` with zero target matches, so there is still no adjacent fixup-slot signature for ASP even without base-pointer resolution.

## Fixups decode audit (chain stepping vs page boundaries)

- New audit `kc_fixups_audit.py` checks whether `next_delta * 4` keeps chains within page boundaries using segment vmaddr + page_size:
  - Run: `PYTHONPATH=$PWD python3 book/experiments/mac-policy-registration/kc_fixups_audit.py --fixups book/experiments/mac-policy-registration/out/kc_fixups.jsonl --fileset-index book/experiments/mac-policy-registration/out/kc_fileset_index.json --summary book/experiments/mac-policy-registration/out/kc_fixups_summary.json --out book/experiments/mac-policy-registration/out/kc_fixups_audit.json`
  - Result: `next_out_of_page_fraction` is very high (`cache_level 0 ≈ 0.479`, `cache_level 2 ≈ 0.951`, `cache_level 1/3 = 1.0`), indicating the current chain walk is inconsistent with page boundaries. This suggests either the page-base mapping is wrong for the fixups segments or the decode assumptions are off; treat fixups decode as **under exploration** until this is resolved.

## Fixups decode correction + re-audit (bit layout)

- Corrected pointer_format 8 bit layout in `_decode_kernel_cache_ptr` to match the documented field order (diversity/addr_div/key precede `next_delta`), then re-ran `kc_truth_layer.py`:
  - New `cache_level_counts`: `{0: 914488}` with `cache_nonzero_fraction = 0.0`; base-pointer inference is no longer gated and all fixups resolve under cache_level 0.
  - `resolved_in_entry_fraction = 1.0`, `resolved_outside_fraction = 0.0` in `kc_fixups_summary.json`.
- Re-ran `kc_fixups_audit.py` with the corrected fixups map:
  - `next_out_of_page_fraction` is now `0.0` for cache_level 0, so chain stepping is consistent with page boundaries.
- Re-ran `asp_conf_fixup_signature_scan.py --allow-unresolved` with the corrected fixups map:
  - `status.resolved = no_adjacent_fixup_slots`, `status.target = no_adjacent_target_slots`, with zero matches.
  - This is stronger evidence that ASP’s `mac_policy_conf` is not statically materialized in BootKC data (or not as adjacent name/fullname slots), rather than an artifact of fixups decoding.

## kc_fixups size control (compact mode)

- `kc_truth_layer.py` now defaults to `--fixups-mode compact`, emitting `kc_fixups.jsonl` with only `{v,r}` pairs to keep the file GitHub‑safe (~48MB).
- Full fixup records are still available via `--fixups-mode full` for local audits; `kc_fixups_audit.py` requires full records and will refuse compact input.

## ASP interprocedural store trace (x0 base) + fixups map OOM

- Added `asp_context_trace` in `kernel_mac_policy_register_instances.py` to scan for stores to `x0/x19 + 0xb10/0xb18/0xb30` around the ASP `mac_policy_register` call and at direct callers (max 40 callers, 80-instruction backtrace).
- Attempting to load the full corrected `kc_fixups.jsonl` inside Ghidra now throws `OutOfMemoryError` after several minutes; the 914k-entry fixups map is too large for the headless Jython heap.
- Workaround: re-ran `kernel-mac-policy-register-instances` with `fixups-mode=skip` to avoid loading the fixups map (partial pointer resolution).
  - Command: `PYTHONPATH=$PWD python3 book/api/ghidra/run_task.py kernel-mac-policy-register-instances --build 14.4.1-23E224 --project-name sandbox_14.4.1-23E224_kc --process-existing --no-analysis --exec --script-args call-sites=book/experiments/mac-policy-registration/out/mac_policy_register_call_sites.json fixups=book/experiments/mac-policy-registration/out/kc_fixups.jsonl fixups-mode=skip fileset-index=book/experiments/mac-policy-registration/out/kc_fileset_index.json mac-policy-register=0x-1fff729bb68 max-back=200`
  - Result: `asp_context_trace` finds the same in-function stores (`str x8,[x19,#0xb10]`, `str x8,[x19,#0xb18]`, `str x20,[x19,#0xb30]` with `x20 = x0 + 0x98`) and a single direct caller with unresolved `x0` (source `func_boundary`), but still no concrete base value.
