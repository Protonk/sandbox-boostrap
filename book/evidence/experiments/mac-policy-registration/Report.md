# mac-policy-registration – Research Report

## Purpose
Recover the sandbox/mac_policy_conf and mac_policy_ops (plus registration site) for this host baseline, across the kernel and sandbox kext slices.

## Baseline & scope
- Host: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5` (Apple Silicon, SIP on).
- Inputs: kernelcache (`book/dumps/ghidra/private/aapl-restricted/14.4.1-23E224/kernel/BootKernelCollection.kc`) with sandbox fileset entry rebuilt to `book/dumps/ghidra/private/aapl-restricted/14.4.1-23E224/kernel/sandbox_kext.bin` (arm64e) and AMFI fileset entry rebuilt to `book/dumps/ghidra/private/aapl-restricted/14.4.1-23E224/kernel/sandbox_kext_com_apple_driver_AppleMobileFileIntegrity.bin`; analyzed Ghidra projects `book/dumps/ghidra/projects/sandbox_14.4.1-23E224` and `book/dumps/ghidra/projects/amfi_kext_14.4.1-23E224`.
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
- `mac_policy_register_instances.json`: per-call-site `mac_policy_conf` decode (name/fullname/ops/flags), plus fileset entry attribution.
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
   - For any ops pointer found, compare table shape against `book/integration/carton/bundle/relationships/mappings/op_table/op_table_map.json` using existing tools.
   - If alignment exists, note it; otherwise mark as non-op-table or unknown.

## Evidence & artifacts
- Ghidra project: `book/dumps/ghidra/projects/sandbox_14.4.1-23E224`.
- AMFI Ghidra project: `book/dumps/ghidra/projects/amfi_kext_14.4.1-23E224`.
- BootKernelExtensions Ghidra project: `book/dumps/ghidra/projects/sandbox_14.4.1-23E224_extensions`.
- Registration-site scans:
  - `book/evidence/dumps/ghidra/out/14.4.1-23E224/sandbox-kext-mac-policy-register/registration_sites.json`
  - `book/evidence/dumps/ghidra/out/14.4.1-23E224/kernel-mac-policy-register/registration_sites.json`
  - `book/evidence/dumps/ghidra/out/14.4.1-23E224/amfi-kext-mac-policy-register/registration_sites.json`
  - `book/evidence/dumps/ghidra/out/14.4.1-23E224/sandbox-kext-adrp-add-scan/adrp_add_scan.json`
- `book/evidence/dumps/ghidra/out/14.4.1-23E224/sandbox-kext-adrp-ldr-scan/adrp_ldr_scan.json`
  - `book/evidence/dumps/ghidra/out/14.4.1-23E224/sandbox-kext-adrp-ldr-got-scan/adrp_ldr_scan.json`
  - `book/evidence/dumps/ghidra/out/14.4.1-23E224/sandbox-kext-data-define/data_refs.json`
  - `book/evidence/dumps/ghidra/out/14.4.1-23E224/sandbox-kext-block-disasm/disasm_report.json`
  - `book/evidence/dumps/ghidra/out/14.4.1-23E224/sandbox-kext-stub-got-map/stub_got_map.json`
  - `book/evidence/dumps/ghidra/out/14.4.1-23E224/kernel-collection-stub-got-map/stub_got_map.json`
  - `book/evidence/dumps/ghidra/out/14.4.1-23E224/kernel-collection-stub-call-sites/stub_call_sites.json`
  - `book/evidence/dumps/ghidra/out/14.4.1-23E224/kernel-collection-string-call-sites/string_call_sites.json`
  - `book/evidence/dumps/ghidra/out/14.4.1-23E224/kernel-mac-policy-register-anchor/mac_policy_register_anchor.json`
  - `book/evidence/dumps/ghidra/out/14.4.1-23E224/kernel-mac-policy-register-instances/mac_policy_register_instances.json`
  - `book/evidence/dumps/ghidra/out/14.4.1-23E224/sandbox-kext-arm-const-base-scan/arm_const_base_scan.json`
  - `book/evidence/dumps/ghidra/out/14.4.1-23E224/sandbox-kext-got-ref-sweep/got_ref_sweep.json`
  - `book/evidence/dumps/ghidra/out/14.4.1-23E224/sandbox-kext-got-load-sweep/got_load_sweep.json`
  - `book/evidence/dumps/ghidra/out/14.4.1-23E224/amfi-kext-block-disasm/disasm_report.json`
  - `book/evidence/dumps/ghidra/out/14.4.1-23E224/amfi-kext-function-dump/function_dump.json`
  - `book/evidence/dumps/ghidra/out/14.4.1-23E224/amfi-kext-got-ref-sweep/got_ref_sweep.json`
  - `book/evidence/dumps/ghidra/out/14.4.1-23E224/amfi-kext-got-load-sweep/got_load_sweep.json`
  - `book/evidence/dumps/ghidra/out/14.4.1-23E224/kernel-imports/external_symbols.json`
  - `book/evidence/dumps/ghidra/out/14.4.1-23E224/kernel-collection-imports/external_symbols.json`
  - `book/evidence/dumps/ghidra/out/14.4.1-23E224/kernel-string-refs/string_references.json`
  - `book/evidence/dumps/ghidra/out/14.4.1-23E224/kernel-adrp-add-scan/adrp_add_scan.json`
  - `book/evidence/dumps/ghidra/out/14.4.1-23E224/kernel-adrp-ldr-scan/adrp_ldr_scan.json`
  - `book/evidence/dumps/ghidra/out/14.4.1-23E224/kernel-imm-search/imm_search.json`
  - `book/evidence/experiments/mac-policy-registration/out/otool_indirect_symbols.txt`
  - `book/evidence/experiments/mac-policy-registration/out/otool_indirect_symbols_amfi.txt`
- `book/evidence/experiments/mac-policy-registration/out/otool_indirect_symbols_kc.txt`
- `book/evidence/experiments/mac-policy-registration/out/stub_targets.json`
- `book/evidence/experiments/mac-policy-registration/out/stub_targets_kc.json`
- `book/evidence/experiments/mac-policy-registration/out/kc_fileset_index.json`
- `book/evidence/experiments/mac-policy-registration/out/kc_fixups_summary.json`
- `book/evidence/experiments/mac-policy-registration/out/kc_fixups.jsonl`
- `book/evidence/experiments/mac-policy-registration/out/asp_conf_fixup_candidates.json`
- `book/evidence/experiments/mac-policy-registration/out/asp_conf_fixup_candidates_full.json`
- `book/evidence/experiments/mac-policy-registration/out/mac_policy_boot_manifest.json`
- `book/evidence/experiments/mac-policy-registration/out/mac_policy_register_call_sites.json`

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
- BootKernelCollection stub/trampoline sweep (`kernel-collection-stub-got-map`) finds only a `__stubs` block; a full exec-block sweep (`scan_all`) still reports `match_count: 0` (`adrp_seen: 718925`), so there is no stub→GOT mapping recovered from the KC.
- `otool -Iv` against BootKernelCollection emits only the file header and no indirect symbol table lines (`otool_indirect_symbols_kc.txt`), so there is no KC indirect-symbol table to join against.
- Stub-target join on the KC yields `stub_count: 0`, `match_count: 0`, `target_count: 0` (`stub_targets_kc.json`), and the BL/B call-site scan finds `call_site_count: 0` (`kernel-collection-stub-call-sites`).
- The BLR/BR register-dataflow path (MOV/MOVK aliasing + signed address normalization) still yields `call_site_count: 0` and `indirect_call_sites: 0`.
- ADRP base scan for the `__auth_got` range (`sandbox-kext-arm-const-base-scan`) reports no ADRP bases in that range (`adrp_seen: 0`, `matches add:0 ldr:0`).
- GOT reference sweep over `__auth_got/__auth_ptr/__got` defines 332 entries and finds 32 with any refs; the auth_got entries for `_mac_policy_register` and `_amfi_register_mac_policy` have `ref_count: 0` (`got_ref_sweep.json`).
- GOT load sweep (`sandbox-kext-got-load-sweep`) finds zero direct refs or computed loads to the target auth_got entries, even with lookback 32 (`got_load_sweep.json`, `total_hits: 0` for the target-only scan).
- A full GOT load sweep (no target filter) yields 766 direct refs, all into `__got`/`__auth_ptr` and none into `__auth_got` (`__got: 765`, `__auth_ptr: 1`, `__auth_got: 0`), so the target auth_got entries remain unreferenced.
- Status: `blocked` for static-only registration-site recovery until stub/GOT resolution (or authenticated indirect-call tracing) is implemented.

### KC truth layer (fileset + chained fixups, partial)
- BootKernelCollection is `MH_FILESET` with 355 fileset entries and 7 top-level segments (`kc_fileset_index.json`), with a segment-interval map built from each entry’s `LC_SEGMENT_64` ranges (1440 intervals; `__LINKEDIT` excluded because it is a shared range across entries, overlap_total=0).
- Top-level `LC_DYLD_CHAINED_FIXUPS` parsed (`fixups_version: 0`, `imports_count: 0`) with pointer_format `8` only; full chain walking (next*4) yields 914,488 fixups across `__DATA_CONST` (894,872) and `__DATA` (19,616), with max chain length 2048 and per-page coverage recorded (`kc_fixups_summary.json` + `kc_fixups.jsonl`). No `DYLD_CHAINED_PTR_START_MULTI` pages observed.
- Fixup decoding now yields `cache_level_counts: {0: 914488}` with `resolved_in_entry_fraction: 1.0` and `resolved_outside_fraction: 0.0` (KC on-disk vmaddr space, slide=0), so no base-pointer inference beyond the seed is needed under the corrected decode.
- Fixups audit run against the full fixups file (stored under `book/dumps/ghidra/private/oversize/mac-policy-registration/`) confirms `cache_level_counts: {0: 914488}` and `next_out_of_page_fraction: {0: 0.0}` in `kc_fixups_audit.json`.
- `kc_fixups.jsonl` is now emitted in **compact** mode by default to stay GitHub‑safe; use `kc_truth_layer.py --fixups-mode full` locally for full fixup records (required by `kc_fixups_audit.py`). Status remains **partial** because higher‑order semantics are still under exploration.
- Full fixups are intentionally kept out of source control because the JSONL routinely exceeds 100 MB and contains host-specific pointer decode detail. They are still valuable for fixup audits and pointer-format debugging. Generate them locally into `book/dumps/ghidra/private/oversize/mac-policy-registration/` (git-ignored) with:
```sh
PYTHONPATH=$PWD python3 book/evidence/experiments/mac-policy-registration/kc_truth_layer.py \
  --build-id 14.4.1-23E224 \
  --fixups-mode full \
  --out-dir book/dumps/ghidra/private/oversize/mac-policy-registration
```

### String-anchored mac_policy_register hunt (partial)
- `kernel-collection-string-call-sites` with queries `Security policy loaded` and `mac_policy_register failed` finds 4 string hits, 4 referencing functions, and 53 call sites (`string_call_sites.json`).
- The function referencing `Security policy loaded: %s (%s)\n` is `FUN_fffffe0008d64498` (entry `0x-1fff729bb68`), with 7 call sites in `__text`.
- Filtering those call sites and mapping them via the segment-interval map yields 7 unique owner entries: `com.apple.security.AppleImage4`, `com.apple.driver.AppleMobileFileIntegrity`, `com.apple.security.quarantine`, `com.apple.AppleSystemPolicy`, `com.apple.iokit.EndpointSecurity`, `com.apple.security.sandbox`, `com.apple.kext.mcx.alr`.
- `kernel-mac-policy-register-instances` now derives `mpc_ops_offset = 0x20` and `mpo_policy_init` offsets `0x398`/`0x3a0` directly from the `mac_policy_register` body, then uses those offsets for pointer recovery.
- Field-write reconstruction now runs whenever name/fullname are missing, so all 7 policies are identifiable:
  - `AppleImage4` / `AppleImage4 hooks`
  - `AMFI` / `Apple Mobile File Integrity`
  - `Quarantine` / `Quarantine policy`
  - `ASP` / `Apple System Policy`
  - `EndpointSecurity` / `Endpoint Security Kernel Extension`
  - `Sandbox` / `Seatbelt sandbox policy`
  - `mcxalr` / `MCX App Launch`
- Global-store fallback now recovers `mpc_ops` for AMFI and mcxalr when the static conf structs are zeroed (`mpc_ops_global_stores` recorded); `mpc_ops` for ASP remains unresolved (still `x0 + 0x98`, no dispatcher-context base recovered).
- Dispatcher-context recovery now accepts read refs and runs a global BLR/BLRA sweep (backtrace depth capped at 60); no dispatcher-context matches surfaced for ASP, so `mpc_ops` is still unresolved.
- Ops-owner attribution uses ops-table sampling with fixup-aware + PAC-canonicalized pointer handling and a 0x6000-byte window. Owners now map to distinct entries: AppleImage4 → `com.apple.security.AppleImage4`, Quarantine → `com.apple.security.quarantine`, Sandbox → `com.apple.security.sandbox`, EndpointSecurity → `com.apple.kernel`, AMFI → `com.apple.kernel`, mcxalr → `com.apple.filesystems.msdosfs`; ASP remains unresolved. Status remains **partial** because ASP ops base and some fixup base pointers are still under exploration.
- ASP fixup signature scan (adjacent `mpc_name`/`mpc_fullname` fixup slots) yields `status: no_adjacent_fixup_slots` with zero matches under the corrected fixups decode (`asp_conf_fixup_candidates.json`).
- Re-run with target-bit matching on the full fixups file (`--allow-unresolved`) also yields zero adjacent matches (`status.target = no_adjacent_target_slots` in `asp_conf_fixup_candidates_full.json`). This is now treated as **positive evidence** that ASP’s `mac_policy_conf` is runtime‑initialized inside an object instance (not statically materialized as a fixup-backed `{name, fullname}` pointer pair) for this world.
- Fixups decode audit (`kc_fixups_audit.py`) with corrected pointer_format 8 bit layout shows chain stepping stays within page boundaries (`next_out_of_page_fraction: 0.0` for cache_level 0). The corrected decode yields `cache_level_counts: {0: 914488}` and `resolved_in_entry_fraction: 1.0`, so the earlier cacheLevel skew and chain drift were decode artifacts. Status remains **partial** but the fixups layer is now internally consistent for BootKC.
- ASP fixup signature scan re-run with the corrected fixups map still finds no adjacent `mpc_name`/`mpc_fullname` fixup slots (both resolved and target-bit modes report zero matches). This strengthens the static conclusion that ASP’s `mac_policy_conf` is not present as a static, fixup-addressable struct in BootKC data for this world, i.e., it is likely runtime-constructed; label remains **partial** until a runtime witness or additional static evidence is captured.
- Added an interprocedural store trace (`asp_context_trace`) to look for writes to `x0/x19 + 0xb10/0xb18/0xb30` around the ASP registration call and its direct callers. With the full corrected fixups map, Ghidra headless OOMs; the trace was run with `fixups-mode=skip` (partial pointer resolution). The trace confirms the in-function stores and a single direct caller, but the caller’s `x0` is still unresolved (`func_boundary`), so no concrete ASP base/ops address emerges. Status remains **partial**.
- Added ASP interprocedural object-relative store-chain collection (`asp_store_chain`) using the compact fixups map. The chain scans the ASP registration function and direct callees (depth ≤ 3) for stores into the ops (`this + 0x98 + window`) and conf (`this + 0xb10 + window`) regions. Results: 22 functions scanned, 22 stores in the ops/conf windows (12 ops, 10 conf), with 9 exec-pointer stores in the ops window; all 9 resolve into `com.apple.AppleSystemPolicy`. This gives owner attribution without resolving an absolute ASP base pointer.
- Added bulk-init (memcpy/bcopy/bzero‑style) detection to the ASP store-chain collector. The detector looks for callsites with dst in the ops/conf windows and a large length argument, then treats direct exec-pointer STRs as patches over any template copy. The current run finds no bulk-init calls (`bulk_inits: 0`), so ASP remains a patch‑only ops map (`ops_template_slots: 0`, `ops_patch_slots: 9`, `ops_slots_merged: 9`). This is consistent with runtime initialization but does not yet surface a bulk template.
- Added an external cross-check for ASP patch offsets: each merged ops slot now includes `absolute_this_offset = 0x98 + slot_offset`, and offsets `{0x128, 0x1b8, 0x298, 0x468}` are labeled against Objective‑See’s AppleSystemPolicy offsets (hook names: `file_check_mmap`, `file_check_library_validation`, `proc_notify_exec_complete`; `0x128` recorded as offset‑only). This is **external/brittle** alignment, not a host witness, but it strengthens the runtime‑init model without requiring an absolute object base.
- Pivoted to policy→hook→implementing‑image attribution by extracting non‑NULL ops callbacks per policy (segment‑interval attribution) and emitting a boot manifest. `build_mac_policy_boot_manifest.py` aggregates per‑policy hooks from `mac_policy_register_instances.json` and writes `mac_policy_boot_manifest.json`. Current hook counts and top owners: AppleImage4 (1, `com.apple.security.AppleImage4`), AMFI (1151, `com.apple.kernel`), Quarantine (6, `com.apple.security.quarantine`), ASP (9, `com.apple.AppleSystemPolicy`), EndpointSecurity (8, `com.apple.iokit.EndpointSecurity`), Sandbox (192, `com.apple.security.sandbox`), mcxalr (80, `com.apple.filesystems.msdosfs`). This closes the attribution loop without relying on absolute `mpc` storage addresses.
- Added handlep storage attribution (`x1`) to each `mac_policy_register` instance and exposed it in the boot manifest (storage kind, owner entry, block, and offset-from-mpc when derivable). This captures the registration-orchestrator witness without asserting runtime handle values.
- Added optional support for a header-derived `mac_policy_ops` layout map (`ops-layout=<path>` in `kernel_mac_policy_register_instances.py`) to bound and name hook extraction. A local header is required to generate the layout; no apple.com download path is used. Use `build_mac_policy_ops_layout.py` with a local/preprocessed `mac_policy.h` to generate a layout JSON (status: **blocked** until a local header is provided).

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

PYTHONPATH=$PWD python3 book/evidence/experiments/mac-policy-registration/match_stub_got.py \
  --build-id 14.4.1-23E224 \
  --stub-map book/evidence/dumps/ghidra/out/14.4.1-23E224/sandbox-kext-stub-got-map/stub_got_map.json \
  --otool book/evidence/experiments/mac-policy-registration/out/otool_indirect_symbols.txt \
  --out book/evidence/experiments/mac-policy-registration/out/stub_targets.json
python3 book/api/ghidra/run_task.py sandbox-kext-mac-policy-register \
  --process-existing --project-name sandbox_kext_14.4.1-23E224 --no-analysis --exec \
  --script-args flow indirect-all all stub-targets=book/evidence/experiments/mac-policy-registration/out/stub_targets.json

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
python3 book/api/ghidra/run_task.py kernel-collection-stub-got-map \
  --process-existing --project-name sandbox_14.4.1-23E224_kc --no-analysis --exec \
  --script-args stub 8 1 all
PYTHONPATH=$PWD python3 book/evidence/experiments/mac-policy-registration/match_stub_got.py \
  --stub-map book/evidence/dumps/ghidra/out/14.4.1-23E224/kernel-collection-stub-got-map/stub_got_map.json \
  --otool book/evidence/experiments/mac-policy-registration/out/otool_indirect_symbols_kc.txt \
  --out book/evidence/experiments/mac-policy-registration/out/stub_targets_kc.json
python3 book/api/ghidra/run_task.py kernel-collection-stub-call-sites \
  --process-existing --project-name sandbox_14.4.1-23E224_kc --no-analysis --exec \
  --script-args stub-targets=book/evidence/experiments/mac-policy-registration/out/stub_targets_kc.json
python3 book/evidence/experiments/mac-policy-registration/kc_truth_layer.py \
  --build-id 14.4.1-23E224
python3 book/api/ghidra/run_task.py kernel-collection-string-call-sites \
  --process-existing --project-name sandbox_14.4.1-23E224_kc --no-analysis --exec \
  --script-args all "Security policy loaded" "mac_policy_register failed"
python3 book/evidence/experiments/mac-policy-registration/derive_mac_policy_call_sites.py

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

otool -Iv book/dumps/ghidra/private/aapl-restricted/14.4.1-23E224/kernel/sandbox_kext.bin \
  > book/evidence/experiments/mac-policy-registration/out/otool_indirect_symbols.txt

otool -Iv book/dumps/ghidra/private/aapl-restricted/14.4.1-23E224/kernel/sandbox_kext_com_apple_driver_AppleMobileFileIntegrity.bin \
  > book/evidence/experiments/mac-policy-registration/out/otool_indirect_symbols_amfi.txt

otool -Iv book/dumps/ghidra/private/aapl-restricted/14.4.1-23E224/kernel/BootKernelCollection.kc \
  > book/evidence/experiments/mac-policy-registration/out/otool_indirect_symbols_kc.txt

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
