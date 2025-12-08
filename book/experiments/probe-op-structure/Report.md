# Probe Op Structure – Research Report (Sonoma baseline)

## Purpose
Design and run richer SBPL probes to surface filter-specific nodes and `field2` values by varying operations, filters, and metafilters. The goal is to overcome the “generic path/name dominance” seen in minimal profiles and extract clearer `field2` ↔ filter-ID signals and structural patterns that other experiments can reuse.

## Baseline & scope
- Host: Sonoma baseline from `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5 (baseline: book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json)` (shared baseline).
- Vocab artifacts: `book/graph/mappings/vocab/ops.json` (196 entries, status: ok) and `filters.json` (93 entries, status: ok).
- Related work:
  - `field2-filters`: tiny single-filter profiles mostly surfaced generic path/name `field2` values.
  - `op-table-operation`: bucket behavior for small operation sets.
  - `node-layout`: structural patterns for nodes/tags with various filter shapes.

## Deliverables / expected outcomes
- A family of richer SBPL probes under `sb/` (and compiled blobs in `sb/build/`) designed to surface filter-specific `field2` values beyond generic path/name scaffolding.
- Anchor- and tag-aware inventories (e.g., `out/tag_inventory.json`, `out/tag_layout_assumptions.json`) and anchor hit tables tying literals → node indices → `field2` where possible.
- Provisional `field2` ↔ filter-ID hypotheses supported by anchor evidence and system-profile cross-checks, documented with clear validation status.
- Structural notes in this report and `Notes.md` that correlate particular tags/branch shapes with filters/metafilters, for reuse by other experiments.
- (Planned) guardrail checks for any `field2` ↔ filter mappings that become stable on this host.

## Plan & execution log
### Completed
- **Current status**
  - Experiment scaffold and initial probes are in place; early decoding confirms the masking problem described above.
  - Segment-aware slicing has been added (minimal Mach-O segment parser in `profile_ingestion.py`), which recovers node regions for complex profiles that previously yielded node_count=0 (e.g., `v8_all_combo`).
  - Anchor maps and an `anchor_scan` tool are in place. Even with segment-aware slicing and byte-level searches (stride 12/16), anchors found in the literal pool do not map to any node bytes or decoded fields (`node_indices` remain empty). Node fields still only show small filter-ID-like values, with no literal offsets (e.g., anchors at offsets ~461/477 in `v1_file_require_any` never appear in node fields/bytes). This confirms that the current heuristic node parsing exposes filter IDs but not literal references; modern node records need a richer decode to recover literal bindings.
  - Decoder now merges tag-layout hints from `out/tag_layout_assumptions.json` and records per-node `record_size` plus section offsets. Anchor scans rerun with the updated decoder still show anchors only in literal pools (no node hits), reinforcing that literal/regex operands remain hidden until a fuller tag-aware decode is implemented.
  - Decoder now also emits `literal_strings_with_offsets` and per-node `literal_refs` (fields plus byte-scan heuristics for literal offsets/absolute offsets/indices). `anchor_scan.py` normalizes prefixed literals (e.g., `Ftmp/foo`) and prefers decoded `literal_refs` over raw byte scans. Anchors now resolve to literal offsets and, for simple probes, to node indices (e.g., `/tmp/foo` in `v1_file_require_any` hits nodes [16,22,30] with field2 values {5,6,0}), though hits remain heuristic.
  - Revised plan focuses on improving node↔literal association:
    - Transition away from the provisional stride-12 heuristic toward a tag-aware node decoder that interprets modern node records (per-tag layouts, 32/64-bit operands) and exposes literal/regex references via the literal/regex tables.
    - Once nodes expose literal links, rerun anchor_scan to resolve anchors → nodes → `field2`.
    - Cross-check anchor hits with system profiles and record evidence tiers; add guardrails once mappings stabilize.
    - Initial tag-aware scaffold (`node_decoder.py`) is wired into literal scans for tag counts, but operands remain small and do not link to literal offsets. We still lack a decode that surfaces literal references; further reverse-engineering of node formats is required.
  - Added coarse tag scans:
    - `tag_inventory.json` (stride-based tag counts/remainders) to sanity-check slicing.
    - `tag_layout_hypotheses.json` (tags {0,5,6,17,26,27} at strides 12/16) with edge in-bounds rates and field2 histograms. Early signals: tags 5/6 parse cleanly under stride-12; high system tags (26/27) are ambiguous (stride-12 yields more records with some out-of-bounds edges; stride-16 yields fewer records, edges in-bounds).
  - Captured initial tag layout assumptions in `out/tag_layout_assumptions.json`:
    - Hypothesis: tags 5 and 6 use 12-byte records with two edge fields and `fields[2]` as the field2 key; edges in-bounds across probes. Literal/regex operand mapping remains open.
    - Tags 26/27 remain pending; stride ambiguity in system profiles needs per-tag layout work before any claim.
  - Generated `tag_inventory.json` (via `tag_inventory.py`) with coarse stride-based tag counts/remainders across probe/system profiles to serve as slicing sanity ahead of per-tag layout hypotheses.
- **1) Scope and setup**
  - Confirmed vocab artifacts (`graph/mappings/vocab/ops.json`, `filters.json`) are `status: ok`.
  - Identified prior experiments (`field2-filters`, `op-table-operation`, `node-layout`) as upstream context for this probe work.
- **1.5) Per-tag inventory (sanity pass)**
  - Performed coarse tag/stride inventories across probe and system profiles (see `tag_inventory` outputs) to sanity-check slicing.
- **2) Improve slicing/decoding**
  - Added segment-aware slicing fallbacks in shared ingestion/decoder code to recover node regions for complex profiles that previously yielded `node_count=0`.
- **3) Anchor-based traversal**
  - Implemented anchor scanning over decoded literal strings and offsets; anchors now resolve to literal offsets and, for simple probes, to node indices via `literal_refs`.
- **4) Probe design (anchor-aware)**
  - Designed and implemented an initial probe matrix (file require-all/any, mach global/local, network socket, iokit class/property, and mixed combos) with distinct anchors.
- **5) Compilation and decoding**
  - Authored SBPL profiles per the initial anchor-aware matrix, compiled them via `libsandbox`, and decoded them with updated slicing.
  - Collected op-table behavior, field2 histograms, and anchor-based node hits in experiment outputs.
- **6) Analysis and mapping**
  - Used anchor hits and field2 inventories to confirm that generic path/name filters dominate small profiles and to motivate tag-aware decoding.
  - Began forming tag-specific layout hypotheses and literal/regex correlation strategies, feeding into the tag-layout-decode experiment.

### Planned
- 1. Improve slicing/decoding for richer profiles (better literal/pool detection; fallback to segment-aware slicing to avoid node_count=0).
  2. Anchor traversal on literals: scan decoded literals for strong anchors (paths, mach names, iokit classes), then map nodes referencing those literals to their `field2` values to isolate filter-specific nodes.
  3. Design profiles with disjoint anchor sets per filter to make literal→filter mapping unambiguous.
  4. Use multi-op profiles where different filter families live on different ops to separate paths during traversal.
  5. Triangulate with system profiles (clear anchors) to confirm mappings.
  6. Cross-op consistency: verify inferred `field2` per filter across ops that share it.
  7. Guardrails: once mappings emerge, add a checker that locates anchor literals in probe blobs and asserts expected `field2` values.
  8. Document evidence tiers: maintain a table of `field2`→filter mappings with provenance and mark uncertain cases.
- **1) Scope and setup**
  - Make the host baseline (OS/build, kernel, SIP) explicit in `ResearchReport.md` as this experiment evolves.
  - `Plan.md`, `Notes.md`, `ResearchReport.md` in this directory.
  - A structured probe matrix describing intended SBPL variants.
- **1.5) Per-tag inventory (sanity pass)**
  - Extend the per-tag inventory once richer tag layouts are available from the tag-layout-decode experiment.
  - Notes on tag byte counts/stride candidates in `Notes.md`; brief summary in `ResearchReport.md`.
- **2) Improve slicing/decoding**
  - Continue to track when fallbacks are used and adjust heuristics as new profile shapes appear.
  - Updated helper script(s) for slicing/decoding richer profiles; note usage in `Notes.md`.
- **3) Anchor-based traversal**
  - Improve tag-aware decoding so anchor-bound nodes can be interpreted reliably in terms of Filters and field2.
  - JSON or notes tying anchor literals → node indices → `field2` → inferred filter.
- **4) Probe design (anchor-aware)**
  - Refine probes to maximize anchor separation and reduce generic path/name masking once node decoding improves.
  - Updated probe matrix in `Notes.md` reflecting anchor choices.
- **5) Compilation and decoding**
  - Recompile/redecode only if new probes or decoder changes warrant it.
  - `sb/` sources and compiled blobs; updated summaries including anchor-based findings.
- **6) Analysis and mapping**
  - Perform a focused analysis of anchor-derived field2 values once node layouts and literal bindings are better understood.
  - Triangulate with system profiles and refine hypotheses into concrete mappings.
  - Updated `ResearchReport.md` with provisional mappings, evidence tiers, and structural notes.
- **7) Guardrails and reuse**
  - Once stable mappings exist, add a checker that locates anchor literals in probe blobs and asserts expected `field2` values.
  - Document how these probes can be reused by other experiments (field2 mapping, op-table alignment) and add guardrail tests accordingly.

## Evidence & artifacts
- SBPL probe profiles and compiled blobs under this directory (`sb/` and `sb/build/`).
- Decoder and slicing enhancements in `book/graph/concepts/validation/profile_ingestion.py` and the tag-aware node decoding scaffold.
- Anchor and tag layout artifacts such as `out/tag_inventory.json`, `out/tag_layout_assumptions.json`, and updated `anchor_hits.json`.
- Running notes in `Notes.md` capturing probe design, decoder changes, and anchor-scan results.

## Blockers / risks
- Modern node formats are still only partially decoded; literal/regex operands remain opaque in many cases, which limits how confidently anchors can be tied to specific nodes and `field2` values.
- Even with richer probes, generic path/name filters continue to dominate many graphs, so filter-specific `field2` signals may remain fragile until tag layouts and operand fields are better understood.

## Next steps
- Improve tag-aware node decoding so literal/regex operands are exposed directly via the literal/regex tables rather than inferred from byte scans.
- Rerun anchor and tag inventories once node layouts stabilize, and use those results to refine `field2` ↔ filter hypotheses.
- Design additional anchor-focused probes that separate filters more cleanly, and coordinate their findings with `field2-filters` and `tag-layout-decode` before promoting mappings to shared artifacts or guardrails.

## Appendix
### What we tried and why it fell short
We implemented a first probe matrix (file require-all/any mixes, mach global/local, network socket filters, iokit class/property, and mixed combos) and compiled them via `libsandbox`. Decoding with vocab padding yielded:

- `field2` values remained dominated by low, generic IDs: `global-name` (5), `local-name` (6), `ipc-posix-name` (4), `file-mode` (3), `remote` (8), regardless of the intended filter mix.
- The network probe surfaced `remote` (8); mach variants surfaced {5,6}; file variants surfaced {3,4} or {5,6}. Mixed profiles showed the same low IDs.
- The “all-combo” profile (`v8`) failed the heuristic decoder (node_count 0), likely due to literal-start detection; richer slicing would be needed there.

Discovery: even with more structure, short op-tables and generic path/name scaffolding mask filter-specific `field2` signals. Graph walks from op-table entries alone tend to hit shared path/name filters instead of the specific filter nodes we’re trying to isolate. This mirrors the earlier field2 experiment and suggests we need better slicing and literal-anchored traversal.

### Status summary (2025-12-09)
- Slicing/decoder: segment-aware slicing works; decoder merges tag-layout hints; literal offsets/refs now emitted. Anchors resolve to offsets and some node indices in simple probes.
- Anchors: `anchor_hits.json` now shows node hits for `/tmp/foo` and `/etc/hosts` in `v1_file_require_any`, and for the mach anchor in `v3_mach_global_local`. Field2 values at those nodes are still generic (global-name/local-name/path), so filter-specific IDs remain masked.
- Remaining work: decode per-tag layouts to expose real literal/regex operands, design anchor-strong probes per filter family, and map those anchor-bound nodes’ field2 values to filter IDs with system-profile cross-checks.

### Expected outcomes
- A set of richer probe profiles that surface filter-specific `field2` values beyond the generic path/name scaffolding.
- Provisional mappings of `field2` ↔ filter-ID supported by multiple probes.
- Structural notes (tags/branch shapes) that correlate with particular filters/metafilters.
- Reusable guardrails for key mappings.

### Next decoding steps (focused)
- **Per-tag inventory:** group decoded nodes by tag across probe/system profiles; record byte counts, candidate strides, and remainders as a coarse sanity check on slicing (front vs tail).
- **Tag-specific layout hypotheses:** for each tag, propose one or two record layouts; evaluate by edge in-bounds rates and whether payload fields plausibly index literal/regex tables; document candidates and evidence in Notes, summarize accepted/rejected layouts here.
- **Literal/regex correlation:** use literal-only deltas (foo→bar, varying literal counts) and system-profile anchors to identify which tag/field positions move with literal content/count; treat that as operand slot evidence once a tag layout is chosen.
