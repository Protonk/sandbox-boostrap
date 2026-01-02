# Manual Ghidra hunt: field2/filter_arg bit handling (Sonoma 14.4.1 KC)

Purpose: hand off a concrete, reproducible path to locate how the kernel evaluator treats the third node payload (field2/filter_arg) in `BootKernelExtensions.kc` (build 14.4.1-23E224). Automated scans for masks/imm constants (0x3fff/0x4000/0xc000/0x00ff/0xff00 and 0xa00/0x4114/0x2a00) returned zero hits, so a guided manual pass is needed.

## Setup

- Open the existing project: `book/dumps/ghidra/projects/sandbox_14.4.1-23E224` (ARM64, pre-analyzed with x86 analyzers disabled).
- Relevant task outputs:
  - `book/dumps/ghidra/out/14.4.1-23E224/kernel-tag-switch/switch_candidates.json` (computed-jump ranking). Top candidates include `FUN_ffffff80005bbb90`, `FUN_ffffff8002377c16`, `FUN_ffffff8000546e60`, `FUN_ffffff80006e9310`, `FUN_ffffff80007f9150`, `FUN_ffffff8002222324`, `FUN_ffffff80008641c0`, `FUN_ffffff80016a17ac`, `FUN_ffffff8000902bb0`, `FUN_ffffff80017b7748`.
  - `book/dumps/ghidra/out/14.4.1-23E224/kernel-op-table/op_table_candidates.json` (op-table scan, mostly dense; may help find entrypoints).
  - `book/dumps/ghidra/out/14.4.1-23E224/kernel-field2-mask-scan/mask_scan.json` and `kernel-imm-search` dirs (all empty for target masks/immediates).

## What to look for

- Goal: find the PolicyGraph evaluator loop that walks node records and see how it consumes the third u16 payload.
- Structural pattern:
  - Per-operation graph traversal using an op-table (array of pointers/indices), then iterating nodes of size ~12 bytes.
  - Loads of two edge fields and a third payload from the node. On ARM64, look for `ldrh`/`ldr` sequences with offsets consistent with tag/edge/payload (common tags use record_size 12; edges at fields[0]/[1], payload at fields[2] per tag layouts).
  - Immediate masking/shifting of the third payload: `and w?, w?, #0x3fff` / `tst w?, #0x4000` / `ubfx`-style. Masks may not be literal (could be synthesized via MOVK/MOVZ) so inspect logical ops immediately after the third load.
  - Uses of the masked value: compare-to-zero, indexing into a table, or branching to helper functions. The hi-bit path might gate “tail” vs “regular” handling.

## Walk plan

1) Start from tag-switch candidates:
   - Visit the top functions in `switch_candidates.json`. For each, examine computed-jump blocks for jump tables or switches that could be op-id or tag dispatch. Look for references to data in the op-table region (see `op_table_candidates.json` offsets) or string refs related to sandbox.

2) Pivot to likely evaluator:
   - From a promising dispatcher, follow callees that operate on memory regions resembling node arrays (pointer arithmetic with small record sizes). Confirm loads of three consecutive halfwords.
   - If you find a function that takes an op-id or node index and loops, bookmark it as the evaluator candidate.

3) Inspect payload handling:
   - Within the candidate, locate where the third u16 is loaded. Check the next few instructions for AND/TST/UBFX using constants or synthesized immediates. Even if no literal mask, note bit ops and destinations.
   - See how the result is used: table index? direct compare? branch target? Calls to helper functions with the payload?

4) Dump and record:
   - If masking/bit-splitting is found, dump disassembly for the function (`kernel-function-dump.py` via run_task or manual “Export Function”) and note:
     - Function name/address.
     - Exact mask/shift and how applied.
     - Use sites (table indexing, branch conditions).
   - If no mask but clear payload use, record how it flows (e.g., passed to helper X at addr Y).

## Where to store findings

- Drop function dumps and notes in `book/dumps/ghidra/out/14.4.1-23E224/kernel-function-dump/` (via `kernel-function-dump.py`) or export text nearby.
- Log observations and dead ends in `Notes.md` (this experiment), with function names/addresses and brief conclusions (“checked, no mask”, “payload passes to helper foo”, etc.).
- If a mask/bitfield scheme is identified, summarize it in `Plan.md` and `troubles/field2-hunting.md` for handoff.

## Caveats

- Automated mask/imm searches found nothing, so masks may be constructed from multiple instructions or applied via generic helpers.
- The op-table output is noisy (many null targets); use it only as a hint for pointer regions, not as a definitive map.
- The string-ref task returned empty; rely on structural cues (tag-switch candidates, node-size arithmetic) rather than string anchors.

## Web agent context

This project is anchored to a single host: macOS 14.4.1 (Apple Silicon), SIP enabled. The goal of this experiment is to understand the third 16-bit field in policy graph nodes (“field2”), which corresponds to the historical `filter_arg` payload in SandBlaster/Blazakis node layouts. Most nodes carry low values that map cleanly to the known filter vocabulary and literal/regex tables (path, mount-relative-path, global/local-name, socket-type, iokit-*). A small set of high values do not map to current vocab or literal indices and only appear in richer graphs:

- Flow-divert mixed network probes show a single node with `field2=2560` (0x0a00) on tag 0 tied to the literal `com.apple.flow-divert`; simplified profiles lose this node.
- The `bsd` platform profile shows `field2` values 170/174/115/109 on tag 26 and a hi-bit value 16660 (0x4114) on tag 0 that behaves like a shared tail (fan_in=33, fan_out=1). Targeted SBPL probes failed to surface these values outside the full profile.
- The `airlock` profile shows high values 165/166/10752 on tags {166,1,0}; not reproduced in simpler probes.

Data model and inventories: field2 is tracked as `field2_raw` with derived `field2_hi = raw & 0xC000` and `field2_lo = raw & 0x3FFF`; unknown/high values are kept as `UnknownFilterArg(field2_raw)`. All current unknowns except bsd’s 16660 have `hi=0`; 16660 has `hi=0x4000`, `lo=0x114`. Unknown-node tables include tags, fan-in/out, and literal refs. Outputs live under `book/experiments/field2-final-final/field2-filters/out/` (inventory, unknown_nodes.json) and `book/dumps/ghidra/out/` for Ghidra tasks.

Automated Ghidra passes on `BootKernelExtensions.kc` (build 14.4.1-23E224):
- `kernel_field2_mask_scan` for masks 0x3fff/0x4000/0xc000/0x00ff/0xff00 (sandbox blocks and full KC): no hits.
- `kernel_imm_search` for 0xa00 (flow-divert), 0x4114 (bsd tail), 0x2a00 (airlock): zero hits each.
- String-ref task yielded no sandbox strings; op-table task output is dense and noisy; tag-switch candidates with high computed jumps are listed earlier (e.g., `FUN_ffffff80005bbb90`, `FUN_ffffff8002377c16`, `FUN_ffffff8000546e60`, etc.) and are likely dispatchers.

Manual next step: locate the PolicyGraph evaluator in the analyzed KC. Start from tag-switch candidates and sandbox-related functions, look for loops loading three u16 fields per node (record size ~12 bytes) and any masks/shifts on the third payload. Even if masks aren’t literals, check nearby logical ops. If masks or bitfield splits are found, dump the function and record exact usage; if not, log inspected functions and flows.

What would help from a web agent: any Sonoma-era knowledge about Sandbox.kext evaluator patterns on ARM64, typical mask idioms for filter_arg/field2 (e.g., synthesized MOVZ/MOVK sequences), known entrypoints or symbol names for the policy graph dispatcher, or private observations of hi-bit/flag usage (0x4000) in macOS 13–14. Suggestions on how Apple might encode internal filters or metafilter glue in modern KC layouts are also useful, since high field2 values likely correspond to undocumented internal filters or flag-augmented arguments. All conclusions must stay version-bound to this host; there is no cross-version stability assumed.
