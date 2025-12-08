# Symbol Search – Research Report (Sonoma baseline, BootKernelExtensions.kc)

## Purpose
Recover the sandbox PolicyGraph dispatcher and adjacent helpers by leveraging symbol/string pivots (AppleMatch imports, sandbox strings, MACF hook tables) and structural signatures, rather than relying on computed-jump density.

## Baseline & scope
- Host target: Sonoma baseline from `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5 (baseline: book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json)` (same baseline as other Ghidra experiments).
- Artifacts: `dumps/Sandbox-private/14.4.1-23E224/kernel/BootKernelExtensions.kc`, Ghidra project `dumps/ghidra/projects/sandbox_14.4.1-23E224`.
- Tooling: headless Ghidra scripts in `book/api/ghidra/scripts/` (string refs, tag switch, op-table), `scaffold.py` with `--process-existing` to reuse the analyzed project.
- Concept anchors: dispatcher should walk compiled PolicyGraph nodes (two successors, action terminals), consult operation→entry tables, call AppleMatch for regex filters, and sit downstream of MACF hook glue.
- Practical note: headless needs `JAVA_TOOL_OPTIONS=-Duser.home=$PWD/dumps/ghidra/home` (plus `GHIDRA_JAVA_HOME`), otherwise it tries to write under `~/Library/ghidra/` which is blocked by the workspace sandbox.

## Deliverables / expected outcomes
- Deliverables: this plan, `Notes.md`, `ResearchReport.md`; `out/` for scratch JSON listings if needed.
- Deliverables: refreshed headless outputs under `dumps/ghidra/out/.../kernel-string-refs` (or a new task) with expanded queries and caller counts.
- Deliverables: shortlists of AppleMatch callers plus addresses/functions, with notes in `Notes.md`.
- Deliverables: function addresses and linkage notes tying MACF hooks to the dispatcher, logged in `Notes.md`.
- Deliverables: signature JSON in `out/` if needed, plus scan results with candidate addresses.
- Deliverables: summary in `ResearchReport.md` of evidence-backed dispatcher candidates and recommended next probes.

## Plan & execution log
### Completed
- **1) Scope and setup**
  - Scaffolded this experiment directory (Plan, Notes, ResearchReport). Inputs: `dumps/Sandbox-private/14.4.1-23E224/kernel/BootKernelExtensions.kc`, analyzed Ghidra project `dumps/ghidra/projects/sandbox_14.4.1-23E224`, headless scripts under `book/api/ghidra/scripts/`.

### Planned
- String/import searches for AppleMatch helpers and sandbox identifiers, with caller enumeration.
  - MACF `mac_policy_conf` / `mac_policy_ops` traversal to find the shared sandbox check helper invoked by `mpo_*` hooks.
  - Header/section signature scans using `.sb.bin` fixtures to find embedded profile structures in KC.
  - Cross-correlation of the above to nominate dispatcher/action-handling functions for deeper analysis.
- **1) Scope and setup**
  - Confirm baseline metadata in `ResearchReport.md` (OS/build, SIP, tools).
- **3) AppleMatch import pivot**
  - Enumerate Sandbox.kext externals/imports and specifically hunt for AppleMatch exports `_matchExec` / `_matchUnpack` (or close variants). Collect callers.
  - Cross-check callers against MACF-hook helpers (shared `(cred, op_id, …)` path) to converge on the PolicyGraph node walker.
  - Use caller intersection (AppleMatch import users ∩ op-table indexers) as the primary dispatcher shortlist.
- **4) MACF hook and mac_policy_ops pivot**
  - Locate the sandbox `mac_policy_conf`/`mac_policy_ops` struct; trace `_mpo_*` entries into the shared helper (`cred_sb_evaluate`/`sb_evaluate_internal`-like).
  - Follow that helper into the inner `eval`-like routine that indexes an op-entry table and walks nodes; intersect with AppleMatch caller set to validate dispatcher identity.

## Evidence & artifacts
- Ghidra project `dumps/ghidra/projects/sandbox_14.4.1-23E224` with analyzed BootKernelExtensions.kc for this host.
- Headless script outputs under `dumps/ghidra/out/...` for kernel string-reference and pointer-table tasks (e.g., `kernel-string-refs`, `kernel-op-table`).
- Notes in `Notes.md` that record query strings, addresses, candidate tables, and interpretation of each scan.
- The underlying kernel cache at `dumps/Sandbox-private/14.4.1-23E224/kernel/BootKernelExtensions.kc` used by all of these runs.

## Blockers / risks
- AppleMatch imports and sandbox-related externals have not yet been located in a way that yields useful callers; string-table hits alone do not connect to real dispatcher code.
- Some pointer tables with promising shapes appear unreferenced under the current analysis, so their relationship to op-table or dispatcher logic remains speculative.
- Headless runs depend on correct Ghidra configuration (ARM64 analyzers, writable Ghidra home in the sandbox); misconfiguration can silently reduce coverage.

## Next steps
- Continue the planned AppleMatch and MACF pivots: enumerate relevant imports/exports, locate `mac_policy_conf` / `mac_policy_ops`, and trace `mpo_*` hooks into shared sandbox helpers.
- Use intersection of MACF hook helpers and any AppleMatch callers as a dispatcher shortlist, then examine those functions’ control flow for PolicyGraph-like evaluation patterns.
- If needed, add focused tasks that look for op-table indexers or profile-parsing constants derived from decoded `.sb.bin` headers to narrow down candidates further.

## Appendix
### Current observations
- Headless string/import scans (all blocks, customizable queries) surface only the known sandbox/AppleMatch strings and no references or external symbols so far, suggesting AppleMatch imports may use different library labels or be inlined; next step is to enumerate external libraries/imports to refine the filter before proceeding to MACF and structure pivots.
- TextEdit `.sb.bin` decode yields op_count=266, magic word=0x1be, nodes_start=548, literal_start=1132; a straight byte signature of the first 32 header bytes does not appear in the KC, so embedded profiles (if any) likely have different preambles or encodings.
- Pointer-table sweep across all KC blocks produced multiple 512-entry tables in `__desc`/`__const` (starts near 0x-7fffef5000) pointing at sandbox-region functions; these are candidates to cross-check against mac_policy_ops or op-entry tables.
- Raw byte scan for adjacent words `0x10a, 0x1be` in the KC found three code sites (file offsets ~0x1466090, 0x148fa37, 0x14ffa9f), implying these constants surface as immediates in code rather than as embedded profile headers; mapping these to Ghidra addresses may reveal profile parsing paths.
- Offset→address lookup shows those constant sites map into `__text` functions `FUN_ffffff8001565fc4`, `FUN_ffffff800158f618`, `FUN_ffffff80015ff7a8`. Disassembly dumps show heavy stack setup, structure writes at offsets like `[rdi+0x1328]` / `[rax+0x32f0]`, and calls into helpers (`0xffffff80016c4a16`, `0xffffff80015aaf56`, `0xffffff8002fd0f5e`), but no direct op-table indexing yet.
- The most promising pointer table is at `__const` 0x-7fffdae120: 512 entries, 333 pointing to `FUN_ffffff8000a5f0b0` (90 unique functions total, few nulls). Initial function info shows this target is a tiny stub (8 bytes, DATA ref only), suggesting the real dispatcher is adjacent (data-driven jump or wrapper). Next: inspect the data reference at `0x-7ffcb08ca4` and nearby functions in the table to identify the actual evaluator/walker.
- First pass at ADRP/ADD scanning into the suspected table page (`kernel_page_ref_scan.py`) returned zero hits, likely because reference analysis did not materialize ADRP targets; a follow-up needs to decode ADRP immediates directly.
- Follow-up ADRP+ADD decoder (`kernel_adrp_add_scan.py`) also found zero matches and reported zero ADRP instructions, indicating this KC is decoded as x86_64. Subsequent pointer-materialization searches should target x86 LEA/MOV immediates into the suspected table page instead of ARM64-specific patterns.
- An x86-focused page scan (`kernel_x86_page_scan.py`) that checks absolute and RIP-relative immediates into the page `0xffffff8000251000` likewise found zero matches; addr lookup shows the table/page are undefined data in `__const` with no recorded callers. Next probes should look for indirect materializations (e.g., base-of-const loads plus offsets, or data constants equal to the table pointer) to confirm how the table is reached.
- Overall takeaway: zero-hit x86 scans don’t bear on the op-table hypothesis for this ARM64 build. De-prioritize the table address until ARM64-specific evidence appears; the most promising pivots are ARM ADRP+ADD/LDR walkers in the sandbox text and profile-anchored blob signatures derived from the decoded `.sb.bin`.
- New anchors from web-agent guidance: target MACF hook chain (`mac_policy_ops` → shared `(cred, op_id, …)` helper → `sb_evaluate_internal`/`eval`-like walker) and AppleMatch imports (`_matchExec` / `_matchUnpack`). The dispatcher shortlist should be the intersection of MACF helper callers and AppleMatch import callers.
- Exhaustive external/symbol/string enumeration via `kernel_string_refs.py` (all blocks, `extlib=` for no filter, extra `symsub` queries) found 3 string hits (AppleMatch + sandbox identifiers) and zero external libraries/symbols recorded. External import pivot via symbol table is a dead end in this KC; next steps need GOT/stub analysis or MACF-path tracing.
- Additional `kernel_string_refs` run with explicit `_matchExec`/`_matchUnpack` queries located those names in LINKEDIT only (symbol-table strings; refs from LINKEDIT data to LINKEDIT). Still zero external symbols or in-text refs, so AppleMatch import pivot stalled. `kernel_imm_search` for `com.apple.security.sandbox` string address likewise produced 0 instruction hits. Need a mac_policy_conf/mac_policy_ops pivot or a GOT/stub decoder to progress.
- Scaffold now includes `kernel-data-define` (wrapper for `kernel_data_define_and_refs.py`) to probe pointer tables/strings. First use on candidate tables at `__mod_init_func` 0x-7fffdeffb0 and `__const` 0x-7fffdae120 yielded no xrefs/callers; both remain undefined data. mac_policy_ops remains unlocated.

### Reporting
- `Notes.md`: running log of commands, addresses, and shortlists.
- `Plan.md`: staged steps and stop conditions.
- This report: rationale, baseline, and how each pivot ties back to the Seatbelt concepts (PolicyGraph evaluation, operation vocabulary, sandbox label plumbing).
