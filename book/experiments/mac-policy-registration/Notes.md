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
