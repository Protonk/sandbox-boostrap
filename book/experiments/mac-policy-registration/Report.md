# mac-policy-registration – Research Report

## Purpose
Recover the sandbox/mac_policy_conf and mac_policy_ops (plus registration site) for this host baseline, across the kernel and sandbox kext slices.

## Baseline & scope
- Host: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5` (Apple Silicon, SIP on).
- Inputs: kernelcache (`dumps/Sandbox-private/14.4.1-23E224/kernel/BootKernelCollection.kc`) with sandbox fileset entry rebuilt to `dumps/Sandbox-private/14.4.1-23E224/kernel/sandbox_kext.bin` (arm64e) and AMFI fileset entry rebuilt to `dumps/Sandbox-private/14.4.1-23E224/kernel/sandbox_kext_com_apple_driver_AppleMobileFileIntegrity.bin`; analyzed Ghidra projects `dumps/ghidra/projects/sandbox_14.4.1-23E224` and `dumps/ghidra/projects/amfi_kext_14.4.1-23E224`.
- Out of scope: generic/macOS-cross-version claims; focus only on this world.

## Model (public anchor)
- `struct mac_policy_conf` (public headers): `mpc_name`, `mpc_fullname`, `mpc_labelnames` (all pointers, often NULL), `mpc_labelname_count` (u32 + padding), `mpc_ops`, `mpc_loadtime_flags` (u32), `mpc_field_off` (pointer), `mpc_runtime_flags` (u32), plus optional list/data pointers; registered via `int mac_policy_register(struct mac_policy_conf *mpc, mac_policy_handle_t *handlep, void *xd);`.
- Real kext examples (BlockBlock, Derpkit, etc.) show sparse population: `mpc_labelnames` often NULL, `mpc_labelname_count` = 0, `mpc_loadtime_flags` frequently `MPC_LOADTIME_FLAG_UNLOADOK` (0x2).
- Hard vs soft scan criteria:
  - Hard: candidate base inside `__DATA`/`__DATA_CONST`, pointer-sized alignment, slots readable, pointer-like fields are NULL or within this image, `labelname_count` small (<= 32).
  - Soft (ranked offline): printable ASCII for name/fullname when present, non-NULL ops pointer, loadtime flags in {0x2, 0x4, 0x6}, strings containing “sand/seat/policy”.
- Scan template (64-bit slots):
  0: name ptr (nullable)
  1: fullname ptr (nullable)
  2: labelnames ptr (nullable)
  3: u32 labelname_count (<= 32)
  4: ops ptr (nullable)
  5: u32 loadtime flags
  6: field_off / label slot ptr (nullable)
  7: u32 runtime flags
  8–9: optional list/data pointers (captured but not required)
- Experiment IR (per-candidate JSON):
```json
{
  "image": "com.apple.security.sandbox",
  "address": "0xffffff8000dead00",
  "segment": "__DATA_CONST",
  "slots": {
    "name": "0xffffff8000abc000",
    "fullname": "0xffffff8000abc100",
    "labelnames": "0xffffff8000abc200",
    "labelname_count": 2,
    "ops": "0xffffff8000def000",
    "loadtime_flags": "0x0",
    "field_or_label_slot": "0xffffff8000abc300",
    "runtime_flags": "0x0"
  },
  "string_values": {
    "name": "Sandbox",
    "fullname": "Seatbelt sandbox policy"
  }
}
```

## Deliverables
- `mac_policy_conf_candidates.json`: candidate structs (name/fullname/labelnames/ops pointers, segment/section, offsets).
- `mac_policy_conf_candidates_ranked.json`: offline-ranked shortlist (string/flag/ops hints) derived from the raw candidates.
- `registration_sites.json`: call sites (address, target, observed args) that appear to register sandbox/mac_policy_conf/mac_policy_ops.
- Notes on any linkage between mac_policy_ops and the op-table mapping for this world.

## Plan (initial)
1) Gather struct layout ground truth from host artifacts:
   - Extract mac_policy_* strings and walk XREFs to locate code that references them.
   - Identify data structures near those references that match a plausible mac_policy_conf layout (pointers to name/fullname/ops, etc.).
2) Sandbox kext surface:
   - Run string/import census over the sandbox kext slice.
   - Scan its `__DATA_CONST`/`__DATA` for structs matching mac_policy_conf shape; record candidates.
3) Registration trace:
   - From functions that reference mac_policy_* strings, record call sites and arguments that look like mac_policy_register-style calls.
   - Emit `registration_sites.json` with addresses, targets, and pointer args (conf/ops candidates).
4) Ops linkage check:
   - For any ops pointer found, compare table shape against `book/graph/mappings/op_table/op_table.json` using existing tools.
   - If alignment exists, note it; otherwise mark as non-op-table or unknown.

## Evidence & artifacts
- Ghidra project: `dumps/ghidra/projects/sandbox_14.4.1-23E224`.
- AMFI Ghidra project: `dumps/ghidra/projects/amfi_kext_14.4.1-23E224`.
- BootKernelExtensions Ghidra project: `dumps/ghidra/projects/sandbox_14.4.1-23E224_extensions`.
- Registration-site scans:
  - `dumps/ghidra/out/14.4.1-23E224/sandbox-kext-mac-policy-register/registration_sites.json`
  - `dumps/ghidra/out/14.4.1-23E224/kernel-mac-policy-register/registration_sites.json`
  - `dumps/ghidra/out/14.4.1-23E224/amfi-kext-mac-policy-register/registration_sites.json`
  - `dumps/ghidra/out/14.4.1-23E224/sandbox-kext-adrp-add-scan/adrp_add_scan.json`
- `dumps/ghidra/out/14.4.1-23E224/sandbox-kext-adrp-ldr-scan/adrp_ldr_scan.json`
  - `dumps/ghidra/out/14.4.1-23E224/sandbox-kext-adrp-ldr-got-scan/adrp_ldr_scan.json`
  - `dumps/ghidra/out/14.4.1-23E224/sandbox-kext-data-define/data_refs.json`
  - `dumps/ghidra/out/14.4.1-23E224/sandbox-kext-block-disasm/disasm_report.json`
  - `dumps/ghidra/out/14.4.1-23E224/sandbox-kext-stub-got-map/stub_got_map.json`
  - `dumps/ghidra/out/14.4.1-23E224/sandbox-kext-arm-const-base-scan/arm_const_base_scan.json`
  - `dumps/ghidra/out/14.4.1-23E224/sandbox-kext-got-ref-sweep/got_ref_sweep.json`
  - `dumps/ghidra/out/14.4.1-23E224/sandbox-kext-got-load-sweep/got_load_sweep.json`
  - `dumps/ghidra/out/14.4.1-23E224/amfi-kext-block-disasm/disasm_report.json`
  - `dumps/ghidra/out/14.4.1-23E224/amfi-kext-function-dump/function_dump.json`
  - `dumps/ghidra/out/14.4.1-23E224/amfi-kext-got-ref-sweep/got_ref_sweep.json`
  - `dumps/ghidra/out/14.4.1-23E224/amfi-kext-got-load-sweep/got_load_sweep.json`
  - `dumps/ghidra/out/14.4.1-23E224/kernel-imports/external_symbols.json`
  - `dumps/ghidra/out/14.4.1-23E224/kernel-collection-imports/external_symbols.json`
  - `dumps/ghidra/out/14.4.1-23E224/kernel-string-refs/string_references.json`
  - `dumps/ghidra/out/14.4.1-23E224/kernel-adrp-add-scan/adrp_add_scan.json`
  - `dumps/ghidra/out/14.4.1-23E224/kernel-adrp-ldr-scan/adrp_ldr_scan.json`
  - `dumps/ghidra/out/14.4.1-23E224/kernel-imm-search/imm_search.json`
  - `book/experiments/mac-policy-registration/out/otool_indirect_symbols.txt`
  - `book/experiments/mac-policy-registration/out/otool_indirect_symbols_amfi.txt`
  - `book/experiments/mac-policy-registration/out/stub_targets.json`

## Status
- Rebuilt sandbox kext from `BootKernelCollection.kc` via `rebuild_sandbox_kext.py` (LC_FILESET_ENTRY `com.apple.security.sandbox`), fixing load-command offsets and producing an arm64e Mach-O (~90 MB) suitable for Ghidra import. Script now supports `--all-matching` (enumerate/rebuild fileset names containing sandbox/seatbelt); this world only exposes `com.apple.security.sandbox` (also emitted as `sandbox_kext_com_apple_security_sandbox.bin`).
- Scanner relaxed to hard-vs-soft checks (hard: data/const ranges, aligned readable slots, pointer-inside-image-or-NULL by default, `labelname_count` <= 32; soft: printable strings, ops presence, flag hints). Captures optional list/data slots and emits soft scores for offline ranking.
- Baseline scan (pointers constrained to image) yielded `candidate_count: 82`, `probe_points: 16495`, `bytes_scanned: 132195` (scan_slots=10) over `__DATA_CONST`/`__DATA`; all candidates had NULL name/fullname/labelnames/ops pointers, only flags varied.
- Pointer-range-relaxed calibration (`--script-args any-ptr`) yields `candidate_count: 118` with 36 candidates containing any non-zero pointer-like slot but still no printable strings and no in-image ops/labelnames; values appear as PAC-ish constants rather than a populated mac_policy_conf.
- Added offline filter `filter_conf_candidates.py`, emitting `mac_policy_conf_candidates_ranked.json` (post-relaxation run confirms only flag-heavy, pointer-null or pointer-out-of-image structs).
- `_read_ascii` guard added in the scanner to drop invalid pointers after a MemoryAccessException on the first arm64e run.

### Static kext search result (ok-negative)
- Scope: reconstructed all sandbox/seatbelt LC_FILESET_ENTRY slices for this world; only `com.apple.security.sandbox` exists.
- Method: ran `sandbox-kext-conf-scan` over `sandbox_kext.bin` (`__DATA_CONST` + `__DATA`) with pointer-constrained and pointer-relaxed templates based on the public `mac_policy_conf` layout (interleaved pointer slots for name/fullname/labelnames/ops plus small integer/flag fields).
- Findings:
  - Pointer-constrained pass: 82 candidates across ~132 KB / 16,495 probe points; all pointer slots NULL, only flag fields vary.
  - Pointer-relaxed pass: 118 candidates over the same region; 36 carry non-zero “pointer-like” values (PAC-looking), still no printable strings, no in-image ops/labelnames, no mac_policy_conf-like pointer pattern.
  - No additional sandbox/seatbelt fileset entries beyond `com.apple.security.sandbox`; same pattern across canonical and “any-ptr” runs.
- Claim: For `world_id = sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`, there is no static `mac_policy_conf`-shaped structure in sandbox/seatbelt fileset kext data. Static kext scanning for `mac_policy_conf`/`mac_policy_ops` is status: ok-negative. Registration-site recovery is still blocked in static analysis because the authenticated GOT/stub references are not yet mapped to call sites; runtime evidence is a separate (out-of-scope) path.

### Registration-site recovery (static, blocked)
- Expanded `sandbox_kext.bin` scan with `flow indirect-all all` surfaces `_mac_policy_register`/`_amfi_register_mac_policy` as external labels (`target_count: 4`) but still yields `call_site_count: 0` and `indirect_call_sites: 0` (`registration_sites.json`).
- BootKernelCollection has no mac_policy symbol names; `target_count: 0` in `kernel-mac-policy-register` output.
- `otool -Iv` shows the authenticated GOT entries for `_amfi_register_mac_policy` (`0xfffffe00084c7ea8`) and `_mac_policy_register` (`0xfffffe00084c80a0`) inside `__DATA_CONST,__auth_got`, but ADRP+ADD/ADRP+LDR scans and data-define/XREF checks report no callers.
- The indirect-call scan now dumps `auth_got+auth_ptr+got` entries (332 total; no mac_policy symbol names) and still reports `indirect_call_sites: 0`.
- Signed-address normalization in the ADRP+LDR auth_got sweep still yields `0` hits (`adrp_seen: 3452`, `ldr_literal_seen: 0`, `truncated_bases: 1508`).
- A stub→GOT scan over exec blocks (no `__stubs` blocks present in this kext) reports `0` matches (`adrp_seen: 3648`, `branch_seen: 647`, `branch_hits: 0`), so no stub targets match the otool indirect symbols. The joined stub target list is empty (`stub_targets.json`, `target_count: 0`).
- The BLR/BR register-dataflow path (MOV/MOVK aliasing + signed address normalization) still yields `call_site_count: 0` and `indirect_call_sites: 0`.
- ADRP base scan for the `__auth_got` range (`sandbox-kext-arm-const-base-scan`) reports no ADRP bases in that range (`adrp_seen: 0`, `matches add:0 ldr:0`).
- GOT reference sweep over `__auth_got/__auth_ptr/__got` defines 332 entries and finds 32 with any refs; the auth_got entries for `_mac_policy_register` and `_amfi_register_mac_policy` have `ref_count: 0` (`got_ref_sweep.json`).
- GOT load sweep (`sandbox-kext-got-load-sweep`) finds zero direct refs or computed loads to the target auth_got entries, even with lookback 32 (`got_load_sweep.json`, `total_hits: 0` for the target-only scan).
- A full GOT load sweep (no target filter) yields 766 direct refs, all into `__got`/`__auth_ptr` and none into `__auth_got` (`__got: 765`, `__auth_ptr: 1`, `__auth_got: 0`), so the target auth_got entries remain unreferenced.
- Status: `blocked` for static-only registration-site recovery until stub/GOT resolution (or authenticated indirect-call tracing) is implemented.

### AMFI pivot (static, blocked)
- Rebuilt `com.apple.driver.AppleMobileFileIntegrity` into `sandbox_kext_com_apple_driver_AppleMobileFileIntegrity.bin` and imported into `amfi_kext_14.4.1-23E224` (block disasm over `__TEXT` matched 1 executable block).
- `amfi-kext-mac-policy-register` reports `target_count: 6` but `call_site_count: 0` and `indirect_call_sites: 0` (`registration_sites.json`); targets include `_mac_policy_register`, `_amfi_register_mac_policy`, and `__ZL15_policy_initbsdP15mac_policy_conf`, but no call-site edges are recovered.
- `otool -Iv` on AMFI shows `_mac_policy_register` in `__DATA_CONST,__auth_got` at `0xfffffe0007e5c290` (signed `0x-1fff81a3d70`); no `_amfi_register_mac_policy` GOT entry appears (function is internal in `__text`).
- GOT ref sweep (`amfi-kext-got-ref-sweep`) defines 329 entries with 47 refs; the `_mac_policy_register` entry has `ref_count: 0` (`got_ref_sweep.json`).
- GOT load sweep (`amfi-kext-got-load-sweep`) finds zero hits for the target auth_got entry; a full sweep yields 314 direct refs (`__got: 300`, `__auth_ptr: 14`, `__auth_got: 0`), so AMFI has no observable auth_got loads despite the mac_policy entry being present.
- Status: still `blocked` for static registration-site recovery; AMFI mirrors the sandbox-kext auth_got blind spot.

### KC pivot (strings/const, blocked)
- `amfi-kext-function-dump` shows no `_mac_policy_register` call inside `_amfi_register_mac_policy`; `__ZL15_policy_initbsdP15mac_policy_conf` was not recovered as a function in the AMFI project (`function_dump.json`).
- `kernel-imports` with substrings (`mac_policy`, `amfi`, `sandbox`, `seatbelt`, `AppleMobileFileIntegrity`) reports `symbol_count: 0` in BootKernelExtensions (no external imports with those names).
- `kernel-collection-imports` with the same substrings reports `symbol_count: 0` in BootKernelCollection.
- BootKernelExtensions import (`sandbox_14.4.1-23E224_extensions`) + `kernel-string-refs` returns 433 string hits for the mac_policy/amfi/sandbox queries, but all mac_policy-related entries resolve only to `__LINKEDIT` data refs (no executable callers in the string reference list).
- `kernel-adrp-add-scan` for `__ZL10mac_policy` address (`-0x1fff819a290`) and `kernel-adrp-ldr-scan` for the AMFI `_mac_policy_register` auth_got address (`-0x1fff81a3d70`) both report zero matches (ADRPs seen: 60), so no KC materialization is visible in BootKernelExtensions.
- `kernel-imm-search` for AMFI `_mac_policy_register` GOT address (`0xfffffe0007e5c290`) returns `hit_count: 0`.
- Status: `blocked` for static KC-level pivots; no call-site or pointer materialization surfaced via strings or ADRP scans.

## Runbook (registration-site scan, static)
```sh
export GHIDRA_HEADLESS=/opt/homebrew/opt/ghidra/libexec/support/analyzeHeadless
export JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home
export PYTHONPATH=$PWD

python3 book/api/ghidra/run_task.py sandbox-kext-mac-policy-register \
  --process-existing --project-name sandbox_kext_14.4.1-23E224 --exec --script-args flow indirect-all all

python3 book/api/ghidra/run_task.py sandbox-kext-block-disasm \
  --process-existing --project-name sandbox_kext_14.4.1-23E224 --no-analysis --exec \
  --script-args text 4 0 1
python3 book/api/ghidra/run_task.py sandbox-kext-stub-got-map \
  --process-existing --project-name sandbox_kext_14.4.1-23E224 --no-analysis --exec \
  --script-args all 16 1

PYTHONPATH=$PWD python3 book/experiments/mac-policy-registration/match_stub_got.py \
  --build-id 14.4.1-23E224 \
  --stub-map dumps/ghidra/out/14.4.1-23E224/sandbox-kext-stub-got-map/stub_got_map.json \
  --otool book/experiments/mac-policy-registration/out/otool_indirect_symbols.txt \
  --out book/experiments/mac-policy-registration/out/stub_targets.json
python3 book/api/ghidra/run_task.py sandbox-kext-mac-policy-register \
  --process-existing --project-name sandbox_kext_14.4.1-23E224 --no-analysis --exec \
  --script-args flow indirect-all all stub-targets=book/experiments/mac-policy-registration/out/stub_targets.json

python3 book/api/ghidra/run_task.py sandbox-kext-arm-const-base-scan \
  --process-existing --project-name sandbox_kext_14.4.1-23E224 --no-analysis --exec \
  --script-args 0x-1fff7b382e0 0x-1fff7b37981 16 all

python3 book/api/ghidra/run_task.py sandbox-kext-got-ref-sweep \
  --process-existing --project-name sandbox_kext_14.4.1-23E224 --no-analysis --exec \
  --script-args all

python3 book/api/ghidra/run_task.py sandbox-kext-got-load-sweep \
  --process-existing --project-name sandbox_kext_14.4.1-23E224 --no-analysis --exec \
  --script-args 32 all target_only=0x-1fff7b38158,0x-1fff7b38250

python3 book/api/ghidra/run_task.py sandbox-kext-got-load-sweep \
  --process-existing --project-name sandbox_kext_14.4.1-23E224 --no-analysis --exec \
  --script-args 32 all
python3 book/api/ghidra/run_task.py kernel-mac-policy-register \
  --process-existing --project-name sandbox_14.4.1-23E224_kc --no-analysis --exec

python3 book/api/ghidra/run_task.py kernel-imports \
  --process-existing --project-name sandbox_14.4.1-23E224_extensions --no-analysis --exec \
  --script-args mac_policy amfi sandbox seatbelt AppleMobileFileIntegrity
python3 book/api/ghidra/run_task.py kernel-collection-imports \
  --process-existing --project-name sandbox_14.4.1-23E224_kc --no-analysis --exec \
  --script-args mac_policy amfi sandbox seatbelt AppleMobileFileIntegrity
python3 book/api/ghidra/run_task.py kernel-string-refs \
  --project-name sandbox_14.4.1-23E224_extensions --exec \
  --script-args all mac_policy mac_policy_register mac_policy_conf policy_initbsd AppleMobileFileIntegrity amfi sandbox seatbelt
python3 book/api/ghidra/run_task.py kernel-adrp-add-scan \
  --process-existing --project-name sandbox_14.4.1-23E224_extensions --no-analysis --exec \
  --script-args -0x1fff819a290 all
python3 book/api/ghidra/run_task.py kernel-adrp-ldr-scan \
  --process-existing --project-name sandbox_14.4.1-23E224_extensions --no-analysis --exec \
  --script-args -0x1fff81a3d70 all
python3 book/api/ghidra/run_task.py kernel-imm-search \
  --process-existing --project-name sandbox_14.4.1-23E224_extensions --no-analysis --exec \
  --script-args 0xfffffe0007e5c290 all

otool -Iv dumps/Sandbox-private/14.4.1-23E224/kernel/sandbox_kext.bin \
  > book/experiments/mac-policy-registration/out/otool_indirect_symbols.txt

otool -Iv dumps/Sandbox-private/14.4.1-23E224/kernel/sandbox_kext_com_apple_driver_AppleMobileFileIntegrity.bin \
  > book/experiments/mac-policy-registration/out/otool_indirect_symbols_amfi.txt

python3 book/api/ghidra/run_task.py sandbox-kext-adrp-add-scan \
  --process-existing --project-name sandbox_kext_14.4.1-23E224 --exec \
  --script-args 0xfffffe00084c80a0 all
python3 book/api/ghidra/run_task.py sandbox-kext-adrp-ldr-scan \
  --process-existing --project-name sandbox_kext_14.4.1-23E224 --exec \
  --script-args 0xfffffe00084c80a0 all
python3 book/api/ghidra/run_task.py sandbox-kext-adrp-ldr-got-scan \
  --process-existing --project-name sandbox_kext_14.4.1-23E224 --exec \
  --script-args auth_got 32 all
python3 book/api/ghidra/run_task.py sandbox-kext-data-define \
  --process-existing --project-name sandbox_kext_14.4.1-23E224 --exec \
  --script-args addr:0xfffffe00084c80a0 addr:0xfffffe00084c7ea8

python3 book/api/ghidra/run_task.py amfi-kext-block-disasm \
  --project-name amfi_kext_14.4.1-23E224 --exec --script-args text 4 0 1
python3 book/api/ghidra/run_task.py amfi-kext-mac-policy-register \
  --process-existing --project-name amfi_kext_14.4.1-23E224 --no-analysis --exec \
  --script-args flow indirect-all all
python3 book/api/ghidra/run_task.py amfi-kext-function-dump \
  --process-existing --project-name amfi_kext_14.4.1-23E224 --no-analysis --exec \
  --script-args _amfi_register_mac_policy __ZL15_policy_initbsdP15mac_policy_conf
python3 book/api/ghidra/run_task.py amfi-kext-got-ref-sweep \
  --process-existing --project-name amfi_kext_14.4.1-23E224 --no-analysis --exec \
  --script-args all
python3 book/api/ghidra/run_task.py amfi-kext-got-load-sweep \
  --process-existing --project-name amfi_kext_14.4.1-23E224 --no-analysis --exec \
  --script-args 32 all target_only=0x-1fff81a3d70
python3 book/api/ghidra/run_task.py amfi-kext-got-load-sweep \
  --process-existing --project-name amfi_kext_14.4.1-23E224 --no-analysis --exec \
  --script-args 32 all
```
