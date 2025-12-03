# Field2 ↔ Filter Mapping (Sonoma 14.4.1, Apple Silicon)

## Goal
Anchor the third node slot (`filter_arg_raw` / “field2”) in compiled PolicyGraphs to concrete Filter vocabulary entries on this host. Use static decoding plus SBPL probes to turn unknown/high values into evidence-backed mappings and to bound what we do **not** know.

## Baseline & evidence backbone
- Host: macOS 14.4.1 (23E224), Apple Silicon, SIP enabled.
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
  - Helper hunt now prefers `__read16` at `fffffe000b40fa1c`: bounds checks + `ldrh/strh`, no masking. `__read24` (halfword+byte) still used elsewhere.
  - `_eval` at `fffffe000b40d698` masks on 0x7f / 0xffffff / 0x7fffff and tests bit 0x17; no `0x3fff`/`0x4000` masks found. Dumped in `dumps/ghidra/out/14.4.1-23E224/find-field2-evaluator/`.
  - No hits for 0x3fff/0x4000 in evaluator path; earlier mask scans also negative.

## Recent probes & inventories
- Added `sb/bsd_ops_default_file.sb` (ops 0,10,21–27) → only low path/socket IDs + 3584 sentinel; no bsd highs.
- Added `sb/airlock_system_fcntl.sb` (system-fcntl + fcntl-command) → mostly low path/socket IDs + new 0xffff sentinel.
- Inventories refreshed (`harvest_field2.py`, `unknown_focus.py`); op reach now included for unknowns.

## New observations (2026-02-13)
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
- Where (if anywhere) are hi/lo bits of field2 interpreted? Current evaluator dump shows no 0x3fff/0x4000 masking.
- What semantics drive the bsd tail high (16660) and the airlock highs (165/166/10752) and the new 0xffff sentinel?
- Can flow-divert 2560 be tied to a specific filter or tag pattern beyond “triple socket predicates + literal”?

## Next steps (handoff-ready)
1) **Inspect `__read16` consumers**: In Ghidra, walk the caller list above and record how each uses `filter_arg_raw` (direct compares vs table indices). Note any constants or table shapes that could bind the known unknowns (16660/2560/10752/0xffff/3584). Add snippets/notes to the experiment before promoting any mapping.
2) **Structural write-ups per cluster**: Using `unknown_nodes.json` + `tag_layouts.json`, document for bsd/airlock/flow-divert/sample the exact tag shapes, fan-in/out, successors, and op reach, so later helper findings can be slotted in without re-deriving structure.
3) **One last guided probe pass (optional)**: If needed, craft minimal variants that preserve op reach for a target unknown (e.g., bsd ops 0–27, airlock op 162, flow-divert triple require-all) and tweak only default/metafilter wrapping. Record any collapse to low IDs as a negative; stop SBPL iteration thereafter.
4) **Mapping hygiene**: Keep hi/lo split (`field2_hi = raw & 0xc000`, `field2_lo = raw & 0x3fff`) and op reach in outputs; do not add shared mappings until kernel + structural evidence line up.

## Artifacts index
- Inventories: `book/experiments/field2-filters/out/field2_inventory.json`, `out/unknown_nodes.json`.
- Probes: `sb/` sources and `sb/build/*.sb.bin` (including new `bsd_ops_default_file` and `airlock_system_fcntl`).
- Ghidra: `dumps/ghidra/out/14.4.1-23E224/find-field2-evaluator/` (`field2_evaluator.json`, `helper.txt`, `eval.txt`, `candidates.json`).
- Scripts: `harvest_field2.py`, `unknown_focus.py`, `book/api/ghidra/scripts/find_field2_evaluator.py`.

## Risks & constraints
- High values remain sparse and op-empty (except bsd 16660); false positives from generic scaffolding are likely in tiny probes.
- Tag layouts for higher tags (26/27/166) are only partially understood; keep edge-field assumptions aligned with `book/graph/mappings/tag_layouts/tag_layouts.json`.
- Runtime/application of platform blobs is gated; all findings are static unless explicitly validated elsewhere (none yet for these highs).
