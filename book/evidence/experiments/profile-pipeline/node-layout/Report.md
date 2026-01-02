# Node Layout Experiment – Research Report

## Purpose
The synthetic textbook treats compiled sandbox profiles as **PolicyGraphs**: node arrays plus edges derived from SBPL **Operations**, **Filters**, and **Metafilters**, with an **Operation Pointer Table** and shared literal/regex tables.

This experiment asks:

- How are nodes laid out in modern compiled profiles on a Sonoma host?
- How do small SBPL changes (adding Filters, changing literals, mixing filter forms) perturb:
  - the node region,
  - the literal/regex pool,
  - tag distributions,
  - and any candidate “filter key” or “literal index” fields?
- What structural facts can we treat as stable across experiments (format/layout) without over-claiming about vocabulary-level details (Operation IDs, Filter IDs)?

We explicitly do **not** attempt a full reverse-engineering of modern node formats. Instead, we aim for a reproducible structural picture that supports later vocabulary work and capability catalog building.

---

## Baseline & scope
**Host / baseline**

- Sonoma baseline from `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5` (macOS 14.4.1 / 23E224, Apple Silicon, SIP enabled).
- Profiles compiled locally via `libsandbox.dylib` on this host; results are host-specific and aligned with the substrate definitions, and their decoded structure ultimately feeds the static mappings that CARTON freezes for this host.

**Directory contents**

- `Plan.md` – current checklist and open questions.
- `Notes.md` – dated running notes; useful for detailed provenance.
- `sb/` – SBPL variants used as probes.
- `sb/build/*.sb.bin` – compiled policy blobs (one per SBPL variant).
- `analyze.py` – main tooling for this experiment:
  - compiles `sb/*.sb` via `sandbox_compile_string`,
  - slices blobs with `book.graph.concepts.validation.profile_ingestion`,
  - calls `book.api.profile.decoder.decode_profile_dict` (world-scoped stride selection),
  - emits `out/summary.json`.
- `out/summary.json` – machine-readable per-variant summary, including:
  - blob length, heuristic `operation_count`,
  - op-table section length and raw op-table entries,
  - node region length,
  - literal/regex pool length,
  - stride-based stats for the node region (8/12/16),
  - full stride=8 record dump (world-scoped framing) plus a stride=12 dump (historical reference),
  - literal strings extracted heuristically,
  - **decoder** snapshot:
    - `format_variant`,
    - `op_table_offset`,
    - `op_count`,
    - `node_count`,
    - decoder `tag_counts`,
    - decoder `literal_strings`,
    - decoder `sections` lengths,
    - decoder `validation` (stride selection + scaling witnesses).

**Shared tooling from `book/graph/concepts/validation` and `book/api`**

- `profile_ingestion.py` – slices blobs into:
  - 16‑byte preamble,
  - **Operation Pointer Table** bytes,
  - node region bytes,
  - literal/regex pool bytes.
- `book/api/profile/decoder/` – **heuristic modern-profile decoder** that:
  - uses op-table word-offset scaling evidence to select a fixed node stride for this world (stride=8 on the Sonoma baseline),
  - slices the node/literal boundary using an op-table-derived lower bound (to avoid ASCII mis-framing),
  - returns a JSON-friendly dict with:
    - per-node `tag` and `fields`,
    - `node_count` and `tag_counts`,
    - printable strings (with offsets) from the literal/regex pool,
    - `validation` witnesses (stride selection and scaling-pathology scoring).

These tools give us a consistent “slice + decode” view of modern profiles that we use in this experiment and others.

---

## Deliverables / expected outcomes
- A small library of SBPL variants under `sb/` plus compiled blobs under `sb/build/` that exercise representative operation/filter shapes.
- `book/evidence/experiments/profile-pipeline/node-layout/out/summary.json` containing per-variant blob and section lengths, stride statistics, tag counts, and decoder snapshots for this host.
- Narrative notes in `Notes.md` and this Report describing stable format/layout facts for modern compiled profiles on this Sonoma baseline.
- (Planned) lightweight guardrail checks that assert expected format variant and basic layout for a few curated reference profiles.

## Plan & execution log
### Completed
- **1. Baseline ingestion and heuristics**
  - Used the shared ingestion helpers (`book/graph/concepts/validation/profile_ingestion.py`) to:
  - Classify `book/evidence/graph/concepts/validation/fixtures/blobs/sample.sb.bin` as a modern graph-based blob.
  - Slice it into a small preamble/op-table area, a “nodes” region, and a literal/regex tail with human-readable strings.
  - Recorded, for the baseline blob:
  - `operation_count` from the heuristic header and approximate op-table length (`op_count * 2` bytes).
  - Node and literal region lengths.
- Stride scans (8/12/16 bytes) with tag sets and in-bounds edge rates.
- Persisted these observations via `analyze.py` and `out/summary.json`, with narrative in `Notes.md`.
- For ad hoc blob snapshots (section sizes, op-table entries, stride/tag stats, literals), prefer `book/api/profile/` (`inspect` / `decode`) over re-implementing parsers here.
- **2. Synthetic SBPL variants**
  - Added a family of variants under `sb/`:
  - Baseline `file-read*` profile.
  - Subpath-only and dual-subpath profiles.
  - Literal+subpath mixes and multi-literal require-any/require-all shapes.
  - Later probes combining mach-lookup with subpath/literal to stress the layout.
  - Compiled all variants using `sandbox_compile_string` in `analyze.py`.
  - For each variant, recorded blob length, op_count, section lengths (op_table, nodes, literals), and stride/tail statistics into `out/summary.json`.
- **3. Stride and tail behavior**
  - Treated the node region as fixed-size records at strides 8/12/16 for each variant and computed:
  - full-record counts and remainders,
  - distinct tags per stride,
  - in-bounds edge counts.
  - Inspected the last few stride-aligned records and remainder bytes (e.g., v1 vs v4) to identify “tail-only” structure.
  - Established that:
  - no stride yields a remainder-free node region,
  - stride 8 is the decoder-selected framing for this world; other strides are kept as comparative probes and historical context.
- **4. Literal pools and node fields**
  - Inspected literal/regex pools to confirm expected strings across variants (e.g., `/tmp/foo`, `/tmp/bar`, `/etc/hosts`).
  - Compared node regions for key variant pairs:
  - v1 vs v2 (same filter, different literal content) → node bytes identical; only literal tail changes.
  - v1 vs v4 (one vs two subpaths) → shared node prefix with extra tail nodes in v4.
  - v0 vs v5 (baseline vs literal+subpath) → only a small set of node records differ while the literal pool grows.
  - Used extended probes (literal-only and mach+literal/subpath mixes) plus the shared decoder to compare node bytes across mixed filter forms and isolate which changes are structural vs literal-only.
- **5. Op-table anchoring**
  - Extracted op-table entries for each variant using the 0x10 + `op_count` heuristic and persisted them as `op_entries` in `out/summary.json`.
  - Observed:
  - Uniform buckets for small unfiltered profiles (e.g., `[4,…]` vs `[5,…]`),
  - Non-uniform patterns such as `[6,6,6,6,6,6,5]` in mixed mach+filtered-read variants.
  - Used these patterns as structural fingerprints to coordinate with the `op-table-operation` experiment.
- **6. Tooling and artifacts**
  - Implemented `analyze.py` to:
  - compile all `sb/*.sb` into `sb/build/*.sb.bin`,
  - slice blobs into sections,
  - run stride/tail analysis,
  - call the shared decoder to capture `node_count`, tag counts, op_table offsets, literals, section lengths, and stride-selection witnesses,
  - write `out/summary.json` for use by other experiments.
  - Ensured `Notes.md` references `analyze.py`, `out/summary.json`, and key observations.
- **7. Remaining questions and follow-on work**
  - Integrated the shared decoder into the analysis pipeline so that node/tag counts, op_table offsets, and literal strings are available alongside stride stats.
  - Added and studied a family of literal- and mach-heavy probes (two/three/four/five/six/seven+ literal require-any/all variants, mach+literal, mach+subpath), confirming tail-word patterns that change with literal counts and compilation mode.

### Planned
- The `Plan.md` file lists detailed tasks; this section highlights the most impactful next steps for a new agent picking up the experiment.
  
  1. **Tighten node-field ↔ SBPL construct hypotheses**
     - Design additional single-change SBPL variants that:
       - add/remove **exactly one** filter of a given type (`subpath`, `literal`, `global-name`, etc.),
       - swap `require-any` and `require-all`,
       - move the same filter between different operations.
     - For each new variant:
       - re-run `analyze.py`,
       - compare decoder `nodes` and node-field histograms to the nearest baseline,
       - document how the node fields change.
    - Goal: reach a table of the form “node field X consistently appears when construct Y is present” without claiming more than the data supports.
  
  2. **Front vs tail characterization**
     - For a small subset of variants (baseline, single subpath, dual subpath, dual literal, one tag6-heavy mix):
       - choose a cutoff index that separates “front” from “tail” (for example, last index shared with baseline vs new nodes),
       - record tag distributions and field patterns separately for front and tail,
       - look for patterns such as “require-any branch nodes only appear in the tail” or “tag6 nodes cluster at the front”.
     - Encode these observations back into `Notes.md` and update this report if clear patterns emerge.
  
  3. **Minimal mach + literal probe**
     - Add a `mach-lookup` + literal-only profile with no subpath (e.g., mach plus `literal "/etc/hosts"` but no extra read rules) to see whether:
       - op-table entries move into the `[6,…,5]` family,
       - tag6 emerges without additional operations.
     - This will help disentangle “mach vs subpath vs multi-branching” in the tag6 story.
  
  4. **Per-op graph signatures (optional within this experiment)**
     - Reuse the decoder to implement small graph walks from op-table entrypoints (as in the op-table experiment), but keep the output local to this directory:
       - for each op-table entry, record reachable tags and node-field patterns,
       - compare signatures between profiles that differ by a single Operation.
     - This remains ID-agnostic but offers a structural view that can later be tied to an Operation Vocabulary Map.
  
  5. **Integration with vocabulary-mapping work**
     - `book/evidence/graph/mappings/vocab/ops.json` and `filters.json` now exist (`status: ok` from cache harvest):
       - revisit this experiment to label observed tag/field patterns with concrete Operation/Filter IDs where possible,
       - keep a clear line between labels grounded in vocab artifacts and structural hypotheses when node-field semantics remain ambiguous.
  
  6. **Turnover discipline**
     - Keep `Plan.md` and `Notes.md` in sync:
       - whenever you add a new SBPL variant, describe why in `Notes.md` and add a brief bullet in `Plan.md`,
       - when a hypothesis is strengthened or disproved, adjust this report and leave the previous version accessible via git history rather than piling on new ad‑hoc sections.
  
## Evidence & artifacts
- SBPL probe profiles under `sb/` and their compiled blobs in `sb/build/*.sb.bin`.
- `book/evidence/experiments/profile-pipeline/node-layout/analyze.py` as the main ingestion and summary script.
- `book/evidence/experiments/profile-pipeline/node-layout/out/summary.json` with per-variant structural data and decoder output.
- Header/preamble and node-remainder contracts for canonical profiles captured in `book/evidence/graph/mappings/system_profiles/header_contract.json` and `book/evidence/graph/concepts/validation/out/static/node_remainders.json` (guardrailed in `book/tests/planes/contracts/test_header_contract.py` and `book/tests/planes/graph/test_node_remainders.py`).
- Shared ingestion/decoder helpers under `book/graph/concepts/validation/` as referenced in the Baseline & scope section.

## Blockers / risks
- Tail-region layout and any mixed-stride node formats are still not fully characterized; current descriptions are heuristic and may change as decoding improves.
- Field roles within nodes (especially payload fields vs literal indices) are only partially mapped and depend on decoder assumptions.

## Next steps
- Tighten node-field ↔ SBPL-construct hypotheses by adding carefully controlled single-change SBPL variants and comparing updated summaries.
- Further characterize “front” versus “tail” regions for a few reference profiles to see which tags and constructs cluster where, and pair that with the new header/preamble contract so the heuristic slice and remainder bytes are bounded by explicit reference values.
- Add at least one minimal mach+literal probe and compare its node signatures to existing read/write-only variants.
- Coordinate with `op-table-operation` and `tag-layout-decode` once their artifacts stabilize, so this experiment can be annotated with concrete operation and filter IDs where justified.

## Appendix
### 3. SBPL probes and compiled profiles
The SBPL variants in `sb/` are deliberately tiny and tightly controlled. They fall into several families:

1. **Baselines and simple filters**
   - `v0_baseline`: `file-read*` only.
   - `v1_subpath_foo`: `file-read*` with `(subpath "/tmp/foo")`.
   - `v2_subpath_bar`: same as `v1` but `"/tmp/bar"`.
   - `v3_two_filters`: `require-all` over two subpaths (`"/tmp/foo"`, `"/dev"`).
   - `v4_any_two_literals`: `require-any` over two subpaths (`"/tmp/foo"`, `"/tmp/bar"`).
   - `v5_literal_and_subpath`: `require-all` over `literal "/etc/hosts"` and `subpath "/tmp/foo"`.

2. **Operation-mix probes (read/write/mach/network)**
   - `v6_read_write`, `v7_read_and_mach`,
   - `v8_read_write_dual_subpath`,
   - `v9_read_subpath_mach_name`,
   - `v10_read_literal_write_subpath`,
   - `v11_mach_only`, `v12_write_only`, `v13_network_outbound`,
   - `v14_mach_and_network`, `v15_write_and_network`,
   - `v16_read_and_network`, `v17_read_write_network`,
   - `v18_read_mach_network`, `v19_mach_write_network`.

3. **Literal-focused probes**
   - `v20_read_literal`: `file-read*` with `(literal "/etc/hosts")` only.
   - `v21_two_literals_require_any`: `file-read*` with `require-any` over two literals (`"/etc/hosts"`, `"/tmp/foo"`).
   - `v22_mach_literal`: `file-read*` with `(literal "/etc/hosts")` plus `mach-lookup` for `com.apple.cfprefsd.agent`.
   - `v23_mach_two_literals_require_any`: `file-read*` with `require-any` over two literals plus the same `mach-lookup`.
   - `v24_three_literals_require_any`: `file-read*` with `require-any` over three literals (`"/etc/hosts"`, `"/tmp/foo"`, `"/usr/bin/yes"`), no mach.
   - `v25_four_literals_require_any` and `v26_four_literals_require_any_reordered`: `file-read*` with `require-any` over four literals (same set, different order), no mach.
   - `v29_five_literals_require_any` and `v30_six_literals_require_any`: `require-any` extended to five/six literals to probe branch markers.
   - `v27_two_literals_require_all` and `v28_four_literals_require_all`: `file-read*` with `require-all` over literals (two vs four).

Together, these probes let us vary:

- which **Operation** symbols appear,
- which **Filters** (subpath, literal) and **Metafilters** (require-all / require-any) are used,
- how many independent filter “branches” are present,
- and whether extra operations (mach, write, network) are in the same profile.

The compilation step (`analyze.py`) produces matching `*.sb.bin` blobs, guaranteeing that every summary entry is derived from a known SBPL variant.

---

### 4. Structural layout of modern profiles
Across all variants on this host, we see the following structural invariants:

- A 16‑byte preamble, followed by:
  - an **Operation Pointer Table** (`op_count` 16‑bit entries),
  - a node region,
  - a literal/regex pool.
- `profile_ingestion` and the decoder agree on:
  - `op_table_offset = 16` bytes,
  - node and literal section lengths (with minor variations per profile).

The node region behaves like:

- a fixed-size record stream under the decoder-selected stride for this world (stride=8 via the op-table word-offset witness),
- plus a small remainder (node region lengths are often not exact multiples of 8),
- with other stride views (12/16) retained in `out/summary.json` as comparative probes and historical context.

The decoder formalizes this view:

- Treats every 8‑byte chunk as a node:
  - first 2 bytes → `(tag, kind)` bytes (the decoder currently surfaces `tag` directly and carries the full record hex for inspection),
  - next 3 u16 words → `fields` (opaque 16‑bit values, `fields[0..2]`),
  - exposes per-node hex plus `tag_counts`.
- Reports `node_count` in a narrow band for this probe set (48–53 nodes), for example:
  - `v0_baseline`: 48 nodes,
  - `v1_subpath_foo` / `v2_subpath_bar`: 52 nodes,
  - `v8_read_write_dual_subpath` / `v9_read_subpath_mach_name` / `v10_read_literal_write_subpath`: 53 nodes.

We retain stride-based views in `summary.json` for historical comparison, but the decoder is the primary structural lens going forward.

---

### 5. Literal pools and content vs structure
The literal/regex pool behaves exactly as the substrate suggests:

- Human-readable strings (paths, literal filenames, mach service names) appear in the pool, often with a one-byte prefix that encodes type/class:
  - path-like strings: `G/tmp/foo`, `G/tmp/bar`,
  - literal path: `I/etc/hosts`,
  - mach global-name: `Wcom.apple.cfprefsd.agent`,
  - sometimes slightly mangled forms in decoder output: `D/tmp/`, `Bbar`, `\nBfoo`, `\nHetc/hosts`.

However:

- Changing literal **content** in SBPL does not change node bytes, only the pool:
  - `v1_subpath_foo` vs `v2_subpath_bar`:
    - same **Filters** (`subpath`), different literal strings,
    - node regions are bit-identical (same `nodes` list from the decoder),
    - only the literal pools differ (one contains `/tmp/foo`, the other `/tmp/bar`).
- Adding or removing **filters** does change the node region:
  - Adding a single subpath (v1) vs baseline (v0) changes many nodes and increases `node_count` under the stride=8 decoder framing (48→52).
  - Adding a second subpath under `require-any` (v4) does not change the decoded node records vs v1 under the current decoder; it changes the literal pool (adds a second anchor) without perturbing the node region bytes.
  - Adding a literal filter alongside a subpath (v5) changes node bytes while keeping `node_count` baseline-like (48); this is a good “same size, different structure” specimen for future layout work.

Literal byte offsets in the pool (as measured by naive substring search) vary per profile and do **not** line up with any simple node field; this strongly suggests an indirection rather than “node field = literal offset”.

---

### 6. How this experiment feeds the larger project
Within the project’s conceptual model:

- This experiment provides concrete evidence for:
  - the existence and structure of the **Operation Pointer Table** and node region,
  - the role of literal/regex pools in compiled profiles,
  - how **Filters** and **Metafilters** manifest as stable patterns over node tags and small integer fields.
- It supplies reusable artifacts and summaries that:
  - the `op-table-operation` experiment uses to reason about buckets (4/5/6),
  - the `op-table-vocab-alignment` and vocabulary-mapping tasks can leverage once Operation/Filter vocabulary maps exist.

The main value here is not a complete decode of the modern format, but a well-documented, reproducible slice of how today’s Seatbelt PolicyGraphs look on Sonoma, and a clear set of open questions for future agents.***
