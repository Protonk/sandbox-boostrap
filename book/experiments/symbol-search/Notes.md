# Symbol Search – Notes

Use this file for dated, concise notes on commands, findings, and pivots.

## 2025-12-30

- Scaffolded experiment (Plan/Notes/ResearchReport). Ghidra inputs: analyzed project `dumps/ghidra/projects/sandbox_14.4.1-23E224`, headless scripts in `book/api/ghidra/scripts/`. Next actions: widen string/import queries and collect caller maps.

## 2025-12-31

- Extended `kernel_string_refs.py` to accept extra args (`all`, `extlib=...`, `symsub=...`) and to run against existing projects via `--process-existing` scaffold flag.
- Runs (no-analysis, reuse project):
  - `all` blocks, defaults → 3 string hits (`AppleMatch`, two sandbox strings), 0 symbol hits, 0 externals.
  - `all extlib=match symsub=match` → same 3 strings, still 0 symbol hits / externals. No references recorded to those strings.
- External library summary is empty (Ghidra reports no external symbols in the KC import table), so the AppleMatch-import pivot needs a different approach (e.g., MACF hook trace or structure signature).
- Conclusion: direct string/import pivots are dry so far; need to enumerate external libraries/imports to adjust filters or pivot to MACF/profile signatures.

## 2025-12-31 (later)

- Parsed TextEdit `.sb.bin` via `book.api.decoder.decode_profile`: op_count=266 (0x10a), magic word=0x1be, early header words `[0, 266, 446, 0, 0, 6, 0, 36, 398, 1113, 1070, ...]`, nodes_start=548, literal_start=1132. Raw 32-byte header signature (little endian) not found in `BootKernelExtensions.kc` via direct byte search.
- Expanded `kernel_op_table.py` to allow `all` blocks; reran headless with `--process-existing --script-args all`. Found 224 pointer-table candidates; largest runs length=512 at `__desc` and multiple `__const` offsets (e.g., start 0x-7fffef5000). First entries point to functions like `FUN_ffffff80003be400`, `FUN_ffffff8000102800`, with many null/unknown targets, suggesting generic function-pointer tables (possible mac_policy_ops candidate to inspect).
- Searched KC bytes for adjacent little-endian words `0x10a, 0x1be`; found three code sites at file offsets 0x1466090, 0x148fa37, 0x14ffa9f (surrounding bytes look like instructions). These constants might appear in profile-parsing paths rather than embedded profile data; need address mapping in Ghidra to inspect callers.

## 2026-01-01

- Added headless `kernel_addr_lookup.py` to map file offsets to addresses/functions/callers; scaffold supports `kernel-addr-lookup`.
- Looked up offsets {0x1466090, 0x148fa37, 0x14ffa9f}: map to `__text` functions `FUN_ffffff8001565fc4`, `FUN_ffffff800158f618`, `FUN_ffffff80015ff7a8` (no instruction bytes retrieved yet; likely need disassembly pass). No callers recorded.
- Pointer table deep-dive: 512-entry table at `__const` start `0x-7fffdae120` has 333 entries pointing to `FUN_ffffff8000a5f0b0` (90 unique functions total, 27 nulls). Other 512-entry tables: `__desc` start `0x-7fffef5000` (4 funcs total) and `__const` start `0x-7fffddf830` (12 funcs). The dense table with a dominant single target looks like a strong op-entry pointer table candidate; target function is the next analysis focus.
- Added `kernel_function_info.py` to dump callers/callees for a named function; run on `FUN_ffffff8000a5f0b0` shows: address `0x-7fff5a0f50` (`__text`), size 8 bytes, one DATA reference from `0x-7ffcb08ca4`, no callees. This suggests `FUN_ffffff8000a5f0b0` is likely a tiny stub (perhaps start of a jump table) rather than the evaluator proper; need to inspect surrounding data/callers.

## 2026-01-02

- Headless needed a writable home dir; set `JAVA_TOOL_OPTIONS=-Duser.home=$PWD/dumps/ghidra/home` (plus `GHIDRA_JAVA_HOME`) to avoid writing under `~/Library/ghidra` (blocked by the workspace sandbox).
- Added `kernel_page_ref_scan.py` (ADRPs/refs into a target page) and `kernel_function_dump.py` (dump disassembly for named functions).
- Ran page-ref scan for candidate table at `0xffffff8000251ee0` (page start `0xffffff8000251000`, 0x1000 size, all blocks): 0 direct refs, 0 ADRP+ADD hits. Likely need a variant that decodes ADRP immediates without relying on reference analysis.
- Dumped functions carrying op-count/magic immediates (`FUN_ffffff8001565fc4`, `...158f618`, `...15ff7a8`); they are full prolog/setup routines touching per-struct offsets (e.g., `[rdi+0x1328]`, `[rax+0x32f0]`) and calling helpers at `0xffffff80016c4a16`/`0xffffff80015aaf56`/`0xffffff8002fd0f5e`. No obvious op-table usage yet; need to trace their callouts and data structures.

## 2026-01-02 (later)

- Added `kernel_adrp_add_scan.py` to decode ADRP+ADD/SUB pairs without relying on references; ran against `BootKernelExtensions.kc` for target `0xffffff8000251ee0` (lookahead 8, all blocks). Result: 0 matches, ADRP count 0, which implies the current KC disassembly is not surfacing ARM64 ADRPs. Do not treat this as x86 evidence; switch to ARM64-aware patterns.
- Added `kernel_x86_page_scan.py` (explicitly x86) to catch absolute or RIP-relative immediates. Ran with target `0xffffff8000251ee0`, page size 0x1000, all blocks → 0 matches after ~4.9M instructions. This is expected on Apple Silicon and should not be used to argue for/against table usage; keep focus on ARM64 ADRP+ADD/LDR and profile-anchored signatures (TextEdit `.sb.bin` layout) to find real table/evaluator usage.
- Data sweep for the suspected table pointer (`0xffffff8000251ee0`) found a single little-endian occurrence at file offset `0x52978` (address `0xffffff8000152978` in `__desc`); no callers/xrefs recorded because the data is undefined in Ghidra. Page start (`0xffffff8000251000`) not found. Next: define that data in Ghidra and chase any refs, or search for nearby ADRP/ADD in ARM64 text.

## 2026-01-03

- Chose to pursue the AppleMatch-import pivot first (per web-agent anchors) before the MACF-hook trace: goal is to enumerate Sandbox.kext externals/imports and hunt for `_matchExec` / `_matchUnpack` (or variants), then intersect their callers with op-table candidates. Rationale: quickest way to get concrete caller sets; MACF chain can follow once imports/callers are known.
- Ran `kernel_string_refs.py` via scaffold (`--process-existing --noanalysis`, args: `all extlib= symsub=match symsub=regex symsub=sandbox`) to exhaustively enumerate externals/strings across all blocks. Result: 3 string hits (AppleMatch + sandbox identifiers), 0 symbol hits, 0 external libraries/symbols recorded. Conclusion: KC has no external symbol entries for AppleMatch (or anything else) in this analysis; need alternative pivots (GOT/stub scanning, mac_policy_ops trace, or direct ARM64 pattern search).
- Re-ran `kernel_string_refs.py` with queries `_matchExec` / `_matchUnpack` (all blocks, default extlib filter). Found LINKEDIT strings `_matchExec`, `_matchUnpack`, `__matchUnpack_3.kalloc_type_view_208`, `__matchUnpack.kalloc_type_view_237` with only LINKEDIT->LINKEDIT data refs (symbol table), and still 0 external symbols. No in-text/function refs surfaced, so AppleMatch import pivot remains blocked without deeper GOT/stub analysis.
- Tried `kernel_imm_search.py` for `com.apple.security.sandbox` data-string address (0xffffff8002dd2920) across all blocks (300s timeout). Hit count: 0. String references are not materializing as immediates in decoded instructions; need another approach (e.g., data-structure walk for mac_policy_conf).
- Added scaffold task `kernel-data-define` to run `kernel_data_define_and_refs.py` for pointer-table/string pivoting. Ran it on candidate tables at `__mod_init_func` 0x-7fffdeffb0 (87 entries) and `__const` 0x-7fffdae120 (512-entry stub table). Result: both addresses stay undefined with 0 recorded callers/xrefs. No progress toward mac_policy_ops via direct table refs.

## 2026-01-04

- Migrated scripts to `book/api/ghidra/scripts/`; reran `kernel_string_refs.py` via scaffold (`--process-existing --noanalysis`, args: `all symsub=mac_policy symsub=sandbox extlib=`). Output: 2 string hits (AppleMatch and com.apple.security.sandbox in `__TEXT`), 0 symbol hits, 0 external libraries, 0 references. Confirms no external import table entries or in-text refs for AppleMatch or mac_policy* substrings. Next pivot: move away from symbol-table/string pivots toward mac_policy_conf/mac_policy_ops struct discovery or GOT/stub pattern scans.
