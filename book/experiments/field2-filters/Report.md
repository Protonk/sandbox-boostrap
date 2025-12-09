# Field2 ↔ Filter Mapping – Research Report (Sonoma baseline) — **Status: complete (negative)**

## Purpose
Anchor the third node slot (`filter_arg_raw` / “field2”) in compiled PolicyGraphs to concrete Filter vocabulary entries on this host. Use static decoding plus SBPL probes to turn unknown/high values into evidence-backed mappings and to bound what we do **not** know yet. This experiment is now **closed**: we have exhausted SBPL probing and kernel struct hunting on this host without finding a kernel-side hi/lo split or a Blazakis-style `[tag, filter, u16 arg, u16 edge0, u16 edge1]` node array. `filter_arg_raw` is read as a plain u16 in the kernel VM; the remaining unknowns stay unmapped.

## Baseline & evidence backbone
- World: Sonoma baseline from `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
- Canonical vocab: `book/graph/mappings/vocab/{filters,ops}.json` (status: ok).
- Canonical profiles: `book/examples/extract_sbs/build/profiles/{bsd,airlock,sample}.sb.bin`.
- Core outputs: `out/field2_inventory.json` (histograms + hi/lo/tag counts) and `out/unknown_nodes.json` (hi/unknown nodes with fan-in/out and op reach).
- Tooling: `harvest_field2.py`, `unknown_focus.py`, Ghidra scripts under `book/api/ghidra/scripts/` (notably `find_field2_evaluator.py`).

## What we know (evidence)
- **Low IDs match vocab**: `bsd` and `sample` map path/socket/iokit filters as expected (e.g., 0=path, 1=mount-relative-path, 3=file-mode, 5=global-name, 6=local-name, 7=local, 8=remote, 11=socket-type, 17/18 iokit, 26/27 right-name/preference-domain, 80 mac-policy-name).
- **High/unknown clusters** (hi=0 unless noted):
  - `flow-divert` literal → `field2=2560` (lo=0xa00) only when socket-domain + type + protocol are all required (mixed probes v4/v7 and `net_require_all_domain_type_proto`); op reach empty.
  - `bsd` tail → `field2=16660` (hi=0x4000, lo=0x114) on tag 0, reachable from ops 0–27 (default/file* cluster). Other bsd highs 170/174/115/109 live on tag 26, op-empty.
  - `airlock` → 165/166/10752 on tags 166/1/0, attached to op 162 (`system-fcntl`).
  - New probe sentinel → `field2=0xffff` (hi=0xc000, lo=0x3fff) in `airlock_system_fcntl` probe on tag 1, no literals.
  - `sample` sentinel → 3584 (lo=0xe00) on tag 0, op-empty.
- **Ghidra (arm64e sandbox kext `/tmp/sandbox_arm64e/com.apple.security.sandbox`)**
  - Helper hunt prefers `__read16` at `fffffe000b40fa1c`: bounds checks + `ldrh/strh`, no masking. `__read24` (halfword+byte) still used elsewhere.
  - `_eval` at `fffffe000b40d698` masks on 0x7f / 0xffffff / 0x7fffff and tests bit 0x17; no `0x3fff`/`0x4000` masks found. Dumped in `dumps/ghidra/out/14.4.1-23E224/find-field2-evaluator/`.
  - No hits for 0x3fff/0x4000 in evaluator path; earlier mask scans also negative.
  - **Struct hunt outcome (definitive):** a dedicated headless scan (`book/api/ghidra/scripts/kernel_node_struct_scan.py`) over all functions reachable from `_eval` in the sandbox kext found **no** fixed-stride `[byte + ≥2×u16]` node layout. Outputs: `dumps/ghidra/out/14.4.1-23E224/find-field2-evaluator/node_struct_scan.txt` and `.json` (0 candidates; only two noisy, non-sandboxy hits). Conclusion: on 14.4.1 the evaluator behaves as a bytecode VM over a profile blob, not a directly indexed node array.

## Recent probes & inventories
- Added `sb/bsd_ops_default_file.sb` (ops 0,10,21–27) → only low path/socket IDs + 3584 sentinel; no bsd highs.
- Added `sb/airlock_system_fcntl.sb` (system-fcntl + fcntl-command) → mostly low path/socket IDs + new 0xffff sentinel.
- Inventories refreshed (`harvest_field2.py`, `unknown_focus.py`); op reach now included for unknowns.

## New observations
- `unknown_nodes.json` summary:
  - `bsd`: 16660 (`hi=0x4000`, `lo=0x114`) on tag 0 with `fan_in=33`, `fan_out=1`, reachable from ops 0–27; other highs 170/174/115/109 sit on tag 26 with `fan_out=1`, `fan_in=0`, op-empty.
  - `airlock`: highs 165/166/10752 on tags 166/1/0; op reach concentrated on op 162 (`system-fcntl`). `airlock_system_fcntl` adds a sentinel 0xffff (hi=0xc000) on tag 1, op-empty.
- `flow-divert`: 2560 only in mixed require-all (domain+type+protocol) probes, tag 0, fan_in=0, fan_out=2→node0, op-empty.
- `sample` and probe clones: sentinel 3584 on tag 0, fan_out=2→node0, op-empty.
- `field2_evaluator.json` shows `__read16` callers worth inspecting: `_populate_syscall_mask`, `_variables_populate`, `_match_network`, `_check_syscall_mask_composable`, `_iterate_sandbox_state_flags`, `_re_cache_init`, `_match_integer_object`, `___collection_init_block_invoke`, `_match_pattern`, `__readstr`, `__readaddr`. No immediates for the unknown constants appear in `eval.txt`, reinforcing that the helper/evaluator passes the u16 through unmasked.
- Obstacle: direct `llvm-objdump` on the carved sandbox binary (whole file or slices) reports “truncated or malformed object” / “not an object file,” so caller disassembly needs to go through Ghidra. Plan: add a headless script to dump those callers from the existing `sandbox_field2_sbx` project and log how the `__read16` result is consumed.
- Follow-up obstacle: first headless Ghidra attempt failed with the usual JDK prompt (`java_home.save` permission; “Unable to prompt user for JDK path, no TTY”). Remedy is to rerun with the established Ghidra env (`JAVA_HOME`/`-vmPath` set, HOME/GHIDRA_USER_HOME in `dumps/ghidra/user`) via the repo’s wrappers before dumping callers.
- Latest status: second headless retry with explicit `JAVA_HOME`/`-vmPath` and repo-local HOME still hit the JDK prompt error. Next actions: invoke via `book/api/ghidra/run_task.py` (which sets `JAVA_TOOL_OPTIONS` and HOME), or set `JAVA_TOOL_OPTIONS=-Duser.home=$PWD/dumps/ghidra/user` explicitly in the headless call. If headless keeps failing, fall back to an interactive Ghidra export of the caller disassembly.
- Resolution: using `JAVA_TOOL_OPTIONS="-Dapplication.settingsdir=$PWD/.ghidra-user -Duser.home=$PWD/dumps/ghidra/user"` plus repo-local HOME/GHIDRA_USER_HOME, headless now runs and dumps caller disassembly to `dumps/ghidra/out/14.4.1-23E224/find-field2-evaluator/read16_callers.txt`. Quick scan: callers mask the payload with `0xffff` in control flow but do not compare against the high field2 constants (0xa00/0x4114/0x2a00/0xffff/0xe00); paths mostly gate indices and bail to error stubs.

## Open questions
- Where (if anywhere) are hi/lo bits of field2 interpreted? Current evaluator dump shows no 0x3fff/0x4000 masking; any semantics must arise from raw-u16 compares/table lookups that we have not yet found.
- What semantics drive the bsd tail high (16660) and the airlock highs (165/166/10752) and the new 0xffff sentinel?
- Can flow-divert 2560 be tied to a specific filter or tag pattern beyond “triple socket predicates + literal”?

## Final status and follow-on (experiment closed)
- SBPL probing and tag/layout census are complete for this host; unknowns remain unmapped but tightly bounded by `unknown_nodes.json`.
- Kernel-side struct search is complete: no fixed node array is visible; `_eval` + helpers read `filter_arg_raw` as a raw u16 without hi/lo masking.
- Further progress would require new work *outside* this experiment scope (e.g., targeted helper-level compares/table lookups or userland `libsandbox` compiler analysis). Record any such follow-ups as new experiments or troubles, not here.

## Anchor-aware structure (sibling experiment)

High/unknown `field2` IDs on this host—such as 16660 (`bsd` tail), 165/166/10752 (`airlock`), 2560 (`flow-divert`), and 3584 (`sample`)—are **structurally situated** by `book/experiments/probe-op-structure` via anchors and tags, even though their semantics remain unmapped here. That experiment:

- Provides `book/experiments/probe-op-structure/out/anchor_hits.json`, which binds concrete anchors (e.g., `/etc/hosts`, `/var/log`, `preferences/logging`, `flow-divert`, `IOUSBHostInterface`, `idVendor`) to node indices and `field2` values under the canonical tag layouts.
- Summarizes, in `book/experiments/probe-op-structure/Report.md`, an **“Anchor status summary for this world”** table that distinguishes structurally solid anchors (pinned `filter_id` with guardrail-backed witnesses) from anchors that remain `status: "blocked"`.
- Feeds the curated anchor layer in `book/graph/mappings/anchors/anchor_filter_map.json`, whose consistency with `anchor_hits.json` is enforced by `book/tests/test_anchor_filter_alignment.py`.

**Usage rule for new agents:** when interpreting `out/field2_inventory.json` and `out/unknown_nodes.json` in this experiment, use the **solid anchors** from `probe-op-structure` (as listed in its Anchor status summary and in `anchor_filter_map.json`) as your safest examples of how specific anchors sit in the graph. Do **not** infer semantics for high/unknown `field2` values beyond what is explicitly recorded in the Limitations/Non-claims sections of both experiments; treat the high IDs in this report as structurally bounded but semantically opaque for this world.

## Artifacts index
- Inventories: `book/experiments/field2-filters/out/field2_inventory.json`, `out/unknown_nodes.json`.
- Probes: `sb/` sources and `sb/build/*.sb.bin` (including new `bsd_ops_default_file` and `airlock_system_fcntl`).
- Ghidra (evaluator/helper): `dumps/ghidra/out/14.4.1-23E224/find-field2-evaluator/` (`field2_evaluator.json`, `helper.txt`, `eval.txt`, `candidates.json`).
- Ghidra (struct hunt, negative): `dumps/ghidra/out/14.4.1-23E224/find-field2-evaluator/node_struct_scan.txt` and `.json` (0 candidates).
- Scripts: `harvest_field2.py`, `unknown_focus.py`, `book/api/ghidra/scripts/find_field2_evaluator.py`, `kernel_node_struct_scan.py`.

## Risks & constraints
- High values remain sparse and op-empty (except bsd 16660); false positives from generic scaffolding are likely in tiny probes.
- Tag layouts for higher tags (26/27/166) are only partially understood; keep edge-field assumptions aligned with `book/graph/mappings/tag_layouts/tag_layouts.json`.
- Runtime/application of platform blobs is gated; all findings are static unless explicitly validated elsewhere (none yet for these highs).
