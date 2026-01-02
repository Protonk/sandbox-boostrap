# Symbol Search – Notes

Use this file for concise notes on commands, findings, and pivots.

## Initial scaffold and inputs

- Scaffolded experiment (Plan/Notes/ResearchReport). Ghidra inputs: analyzed project `book/dumps/ghidra/projects/sandbox_14.4.1-23E224`, headless scripts in `book/api/ghidra/scripts/`. Next actions: widen string/import queries and collect caller maps.

## First string/symbol scans

- Extended `kernel_string_refs.py` to accept extra args (`all`, `extlib=...`, `symsub=...`) and to run against existing projects via `--process-existing` scaffold flag.
- Runs (no-analysis, reuse project):
  - `all` blocks, defaults → 3 string hits (`AppleMatch`, two sandbox strings), 0 symbol hits, 0 externals.
  - `all extlib=match symsub=match` → same 3 strings, still 0 symbol hits / externals. No references recorded to those strings.
- External library summary is empty (Ghidra reports no external symbols in the KC import table), so the AppleMatch-import pivot needs a different approach (e.g., MACF hook trace or structure signature).
- Conclusion: direct string/import pivots are dry so far; need to enumerate external libraries/imports to adjust filters or pivot to MACF/profile signatures.

## Broader scan adjustments

- Parsed TextEdit `.sb.bin` via `book.api.profile.decoder.decode_profile`: op_count=266 (0x10a), magic word=0x1be, early header words `[0, 266, 446, 0, 0, 6, 0, 36, 398, 1113, 1070, ...]`, nodes_start=548, literal_start=1132. Raw 32-byte header signature (little endian) not found in `BootKernelExtensions.kc` via direct byte search.
- Expanded `kernel_op_table.py` to allow `all` blocks; reran headless with `--process-existing --script-args all`. Found 224 pointer-table candidates; largest runs length=512 at `__desc` and multiple `__const` offsets (e.g., start 0x-7fffef5000). First entries point to functions like `FUN_ffffff80003be400`, `FUN_ffffff8000102800`, with many null/unknown targets, suggesting generic function-pointer tables (possible mac_policy_ops candidate to inspect).
- Searched KC bytes for adjacent little-endian words `0x10a, 0x1be`; found three code sites at file offsets 0x1466090, 0x148fa37, 0x14ffa9f (surrounding bytes look like instructions). These constants might appear in profile-parsing paths rather than embedded profile data; need address mapping in Ghidra to inspect callers.

## Kernelcache and Ghidra project setup

- Added headless `kernel_addr_lookup.py` to map file offsets to addresses/functions/callers; scaffold supports `kernel-addr-lookup`.
- Looked up offsets {0x1466090, 0x148fa37, 0x14ffa9f}: map to `__text` functions `FUN_ffffff8001565fc4`, `FUN_ffffff800158f618`, `FUN_ffffff80015ff7a8` (no instruction bytes retrieved yet; likely need disassembly pass). No callers recorded.
- Pointer table deep-dive: 512-entry table at `__const` start `0x-7fffdae120` has 333 entries pointing to `FUN_ffffff8000a5f0b0` (90 unique functions total, 27 nulls). Other 512-entry tables: `__desc` start `0x-7fffef5000` (4 funcs total) and `__const` start `0x-7fffddf830` (12 funcs). The dense table with a dominant single target looks like a strong op-entry pointer table candidate; target function is the next analysis focus.
- Added `kernel_function_info.py` to dump callers/callees for a named function; run on `FUN_ffffff8000a5f0b0` shows: address `0x-7fff5a0f50` (`__text`), size 8 bytes, one DATA reference from `0x-7ffcb08ca4`, no callees. This suggests `FUN_ffffff8000a5f0b0` is likely a tiny stub (perhaps start of a jump table) rather than the evaluator proper; need to inspect surrounding data/callers.

## Extended string/import queries

- Headless needed a writable home dir; set `JAVA_TOOL_OPTIONS=-Duser.home=$PWD/book/dumps/ghidra/home` (plus `GHIDRA_JAVA_HOME`) to avoid writing under `~/Library/ghidra` (blocked by the workspace sandbox).
- Added `kernel_page_ref_scan.py` (ADRPs/refs into a target page) and `kernel_function_dump.py` (dump disassembly for named functions).
- Ran page-ref scan for candidate table at `0xffffff8000251ee0` (page start `0xffffff8000251000`, 0x1000 size, all blocks): 0 direct refs, 0 ADRP+ADD hits. Likely need a variant that decodes ADRP immediates without relying on reference analysis.
- Dumped functions carrying op-count/magic immediates (`FUN_ffffff8001565fc4`, `...158f618`, `...15ff7a8`); they are full prolog/setup routines touching per-struct offsets (e.g., `[rdi+0x1328]`, `[rax+0x32f0]`) and calling helpers at `0xffffff80016c4a16`/`0xffffff80015aaf56`/`0xffffff8002fd0f5e`. No obvious op-table usage yet; need to trace their callouts and data structures.

## Pointer-table candidates and cross-checks

- Added `kernel_adrp_add_scan.py` to decode ADRP+ADD/SUB pairs without relying on references; ran against `BootKernelExtensions.kc` for target `0xffffff8000251ee0` (lookahead 8, all blocks). Result: 0 matches, ADRP count 0, which implies the current KC disassembly is not surfacing ARM64 ADRPs. Do not treat this as x86 evidence; switch to ARM64-aware patterns.
- Added `kernel_x86_page_scan.py` (explicitly x86) to catch absolute or RIP-relative immediates. Ran with target `0xffffff8000251ee0`, page size 0x1000, all blocks → 0 matches after ~4.9M instructions. This is expected on Apple Silicon and should not be used to argue for/against table usage; keep focus on ARM64 ADRP+ADD/LDR and profile-anchored signatures (TextEdit `.sb.bin` layout) to find real table/evaluator usage.
- Data sweep for the suspected table pointer (`0xffffff8000251ee0`) found a single little-endian occurrence at file offset `0x52978` (address `0xffffff8000152978` in `__desc`); no callers/xrefs recorded because the data is undefined in Ghidra. Page start (`0xffffff8000251000`) not found. Next: define that data in Ghidra and chase any refs, or search for nearby ADRP/ADD in ARM64 text.

## Follow-up symbol and string passes

- Chose to pursue the AppleMatch-import pivot first (per web-agent anchors) before the MACF-hook trace: goal is to enumerate Sandbox.kext externals/imports and hunt for `_matchExec` / `_matchUnpack` (or variants), then intersect their callers with op-table candidates. Rationale: quickest way to get concrete caller sets; MACF chain can follow once imports/callers are known.
- Ran `kernel_string_refs.py` via scaffold (`--process-existing --noanalysis`, args: `all extlib= symsub=match symsub=regex symsub=sandbox`) to exhaustively enumerate externals/strings across all blocks. Result: 3 string hits (AppleMatch + sandbox identifiers), 0 symbol hits, 0 external libraries/symbols recorded. Conclusion: KC has no external symbol entries for AppleMatch (or anything else) in this analysis; need alternative pivots (GOT/stub scanning, mac_policy_ops trace, or direct ARM64 pattern search).
- Re-ran `kernel_string_refs.py` with queries `_matchExec` / `_matchUnpack` (all blocks, default extlib filter). Found LINKEDIT strings `_matchExec`, `_matchUnpack`, `__matchUnpack_3.kalloc_type_view_208`, `__matchUnpack.kalloc_type_view_237` with only LINKEDIT->LINKEDIT data refs (symbol table), and still 0 external symbols. No in-text/function refs surfaced, so AppleMatch import pivot remains blocked without deeper GOT/stub analysis.
- Tried `kernel_imm_search.py` for `com.apple.security.sandbox` data-string address (0xffffff8002dd2920) across all blocks (300s timeout). Hit count: 0. String references are not materializing as immediates in decoded instructions; need another approach (e.g., data-structure walk for mac_policy_conf).
- Added scaffold task `kernel-data-define` to run `kernel_data_define_and_refs.py` for pointer-table/string pivoting. Ran it on candidate tables at `__mod_init_func` 0x-7fffdeffb0 (87 entries) and `__const` 0x-7fffdae120 (512-entry stub table). Result: both addresses stay undefined with 0 recorded callers/xrefs. No progress toward mac_policy_ops via direct table refs.

## Notes on blockers and next pivots

- Migrated scripts to `book/api/ghidra/scripts/`; reran `kernel_string_refs.py` via scaffold (`--process-existing --noanalysis`, args: `all symsub=mac_policy symsub=sandbox extlib=`). Output: 2 string hits (AppleMatch and com.apple.security.sandbox in `__TEXT`), 0 symbol hits, 0 external libraries, 0 references. Confirms no external import table entries or in-text refs for AppleMatch or mac_policy* substrings. Next pivot: move away from symbol-table/string pivots toward mac_policy_conf/mac_policy_ops struct discovery or GOT/stub pattern scans.

## ARM64 string refs rerun (AppleMatch + sandbox)

- `python -m book.api.ghidra.run_task kernel-string-refs --process-existing --no-analysis --exec --script-args "all extlib=match symsub=applematch symsub=sandbox symsub=mac_policy symsub=seatbelt AppleMatch applematch _matchExec _matchUnpack AppleSandbox sandbox seatbelt mac_policy mac policy"` (ARM64 processor + `disable_x86_analyzers.py`). Output: `book/evidence/dumps/ghidra/out/14.4.1-23E224/kernel-string-refs/string_references.json` with 190 string hits, 0 symbol hits, 0 AppleMatch externals (lib filter `match`). Queries include a stray `-vmPath ...` because run_task appends vmPath after script args.
- All references are LINKEDIT data refs (symbol-table strings). Non-LINKEDIT hits—including `com.apple.security.sandbox` copies in `__TEXT`/`__data` and mac_policy_* strings—have zero recorded callers. AppleMatch/mac_policy pivots remain string-only with no callable anchors.
- After reordering `-vmPath` ahead of postScript args in the scaffold and rerunning with `extlib=` (no filter), queries are clean (no `-vmPath` in meta), still 190 string hits, 0 symbol hits, 0 externals, and an empty external library summary. No new anchors emerged.

## mac_policy_conf / mac_policy_ops sweep

- `python -m book.api.ghidra.run_task kernel-data-define --process-existing --no-analysis --exec --script-args "addr:0xffffff8002dd2920 addr:0xffffff800020ef10 addr:0xffffff8002650f78 addr:0xffffff8002698000 addr:0xffffff8002726010 addr:0xffffff8002cd1000"`. Targets = sandbox name strings plus a few __const table starts from op_table_candidates.
- Results (`book/evidence/dumps/ghidra/out/14.4.1-23E224/kernel-data-define/data_refs.json`): two targets typed as strings (`com.apple.security.sandbox`, no callers); four targets typed as pointers to `0xffffff8000100000`. Only `0x-7ffd968000` shows a DATA ref from `0x-7ffc3311d0` (no function); other targets have zero callers.
- Follow-up `kernel-addr-lookup` on `0xffffff8003ccee30` (the lone ref site) reports a LINKEDIT address with no data/function metadata. No mac_policy_conf/mac_policy_ops struct located; MACF hook path still unresolved and needs a different pivot (GOT/stub decode or mac_policy registration decomp).
- No dispatcher/helper candidates surfaced to compare against `book/graph/mappings/op_table/op_table.json`; intersection remains empty.

## GOT/import scan (new headless task)

- Added `kernel_imports_scan.py` + scaffold task `kernel-imports` to enumerate externals/GOT stubs and their callers.
- Run: `python -m book.api.ghidra.run_task kernel-imports --process-existing --no-analysis --exec --script-args "applematch mac_policy sandbox seatbelt"`.
- Output: `book/evidence/dumps/ghidra/out/14.4.1-23E224/kernel-imports/external_symbols.json` → `symbol_count: 0` (no externals matched substrings). Import/GOT pivot remains dry; need alternative hooks (mac_policy registration decomp or broader, unfiltered import sweep).
- Unfiltered census: copied `external_symbols.json` to `imports_all.json`; filtered view via `filter_imports.py --substr applematch mac_policy sandbox seatbelt` → `imports_filtered_sandbox.json` with 0 symbols. Kernel imports are ok-negative for these substrings (full census checked).

## mac_policy registration trace attempts (imm-search)

- `kernel_imm_search` for mac_policy_init string address `0xffffff8000c335f4`: 0 instruction hits.
- `kernel_imm_search` for `_mac_policy_register` string address `0xffffff8003c03208`: 0 instruction hits.
- No code refs surfaced from these anchors; registration path remains unresolved and needs a different approach (e.g., decomp from nearby functions or symbol-guided search).

## Dispatcher search and KC disassembly checks

- Re-ran `kernel_tag_switch` against `BootKernelExtensions.kc` (analysis + `--process-existing --no-analysis`): `switch_candidates.json` has `candidate_count: 0`. `kernel_function_dump` and `kernel_function_info` against previously cited `FUN_...` names and `entry` produced no instructions, suggesting the current KC import is not yielding ARM64 disassembly or functions.
- Added `kernel_arm_const_base_scan.py` to scan ADRP bases across a target range; running it on `BootKernelExtensions.kc` for `0xffffff8002650000–0xffffff8002750000` (`all` blocks) reported `adrp_seen: 0`, reinforcing that instruction iteration is empty in this project.

## BootKernelCollection import attempt (tag-switch)

- Attempted to import `BootKernelCollection.kc` into a new Ghidra project (`book/dumps/ghidra/projects/sandbox_14.4.1-23E224_kc`) and run `kernel_tag_switch.py` in the same pass (manual `analyzeHeadless`, ARM64 processor, `disable_x86_analyzers.py`). The run did not finish within 10 minutes or 30 minutes; `book/evidence/dumps/ghidra/out/14.4.1-23E224/kernel-tag-switch-kc/` contains only an empty `script.log` and no `switch_candidates.json`.
- The log shows KC import and analysis start (chained pointer fixups, analysis warnings), so the blocker is wallclock analysis time rather than missing inputs. Next step is the two-phase workflow from `troubles/ghidra_setup.md` (analysis-only run with a generous timeout, then a postScript-only pass) or an analyzer-disabling pre-script to shorten the analysis window.
- Completed the analysis-only run for `BootKernelCollection.kc` using the two-phase approach; analysis succeeded and the project saved (`sandbox_14.4.1-23E224_kc`). Next: run postScript passes (block disassembly + tag-switch).
- PostScript runs on the analyzed KC:
  - `kernel_block_disasm.py` with `block_substr=sandbox` scanned 0 blocks (no sandbox-named memory blocks in BootKernelCollection). The report lists block names like `__TEXT`, `__TEXT_EXEC`, `__text`, `__const`, `__cstring`, etc.
  - `kernel_tag_switch.py` (all blocks) produced 43,722 candidates in `kernel-tag-switch-kc/switch_candidates.json`.
  - `kernel_string_refs.py` (all blocks) returned 3 string hits (AppleMatch + two Sandbox strings) with 0 references.
  - `kernel_adrp_add_scan.py` against the two `com.apple.security.sandbox` addresses and the AppleMatch string address found 0 matches (ADRPs seen ~718,925 each).
- Triaged top tag-switch candidates (size <= 8000, highest computed-jumps) with `kernel_function_dump.py`. `FUN_fffffe00092fb9e0` stands out: repeated ADRP+ADD+LDRSW+ADR+ADD+BR sequences keyed off `w22`, with multiple case-range compares (e.g., `cmp w22,#0x199`, `sub w16,w22,#0x150`, `cmp w16,#0x3d`). This looks like a multi-level jump-table dispatcher, but its role is still under exploration.
- `kernel_function_info.py` shows `FUN_fffffe00092fb9e0` has no code callers and a single data reference from `0xfffffe0007ca4040` (`__const`). `kernel_addr_lookup.py` shows that address contains a pointer to the function, implying it sits in a pointer table.
- Jump-table details for `FUN_fffffe00092fb9e0` (from `kernel_function_dump.py`):
  - Repeated pattern: `cmp w22,#...`, `sub w16,w22,#...`, `cmp w16,#...`, `csel`, `adrp+add` table, `ldrsw`, `adr` base, `br x16`.
  - Table bases observed: `0xfffffe0009300f00`, `0xfffffe00093009f0`, `0xfffffe0009300b88`, `0xfffffe0009300cf8`, `0xfffffe0009300ae8`, `0xfffffe0009300e5c`, `0xfffffe0009301028`, `0xfffffe0009300a64`, `0xfffffe0009300e34`, `0xfffffe0009300acc`, `0xfffffe0009300ff8`.
  - Range gates include comparisons like `cmp w22,#0x199`, `#0x2e`, `#0x172`, `#0x66`, `#0xd7`, `#0x1b7`, `#0x45`, `#0xce`, `#0xbf`, `#0x1a7`. This looks like an op-id range dispatcher but remains unconfirmed.

## Jump-table dump + pointer-table window (KC)

- Added `kernel_jump_table_dump.py` to extract ADRP+ADD+LDRSW jump tables from a function. Running it on `FUN_fffffe00092fb9e0` produced 11 tables with explicit ranges:
  - Example table: `table_addr=0xfffffe0009300f00`, `index_base=0x150` (336), `index_cmp=0x3d` (61), `source_cmp=0x199` (409). Entries resolve to offsets inside `FUN_fffffe00092fb9e0` (case labels), not external functions.
  - Table addresses match the manual ADRP+ADD scan; each table has 7–92 entries depending on the range gate.
- Added `kernel_pointer_table_window.py` to dump pointer windows. The window centered on `0xfffffe0007ca4040` (the sole data ref to `FUN_fffffe00092fb9e0`) shows a dense pointer table with neighboring function pointers (`FUN_fffffe00092fb818`, `FUN_fffffe00092ae994`, `FUN_fffffe000a5db4b0`, etc.). This suggests `FUN_fffffe00092fb9e0` is one entry in a broader dispatch table, but the table is not yet anchored to a sandbox witness.
- Extended `kernel_pointer_table_window.py` with `mode=auto` to expand until non-pointers or block changes. Auto mode finds a 709-entry table spanning `0xfffffe0007ca3360–0xfffffe0007ca4980` in `__const`, with targets in `__text` and `stop_back/stop_forward` both `null_value`. The `FUN_fffffe00092fb9e0` entry sits inside this table (index 412 in the auto dump).
