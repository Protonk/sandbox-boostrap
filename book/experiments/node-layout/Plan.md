# Node Layout Experiment Plan (Sonoma host)

Goal: recover enough of the modern compiled profile node layout to say something concrete about node tags, edges, and (eventually) filter keys, using only local artifacts.

This plan is intentionally high‑level; `Notes.md` and `ResearchReport.md` carry detailed per‑variant logs and findings.

---

## 1. Baseline ingestion and heuristics

**Done**

- Used the shared ingestion helpers (`book/graph/concepts/validation/profile_ingestion.py`) to:
  - Classify `book/examples/sb/build/sample.sb.bin` as a modern graph-based blob.
  - Slice it into a small preamble/op-table area, a “nodes” region, and a literal/regex tail with human-readable strings.
- Recorded, for the baseline blob:
  - `operation_count` from the heuristic header and approximate op-table length (`op_count * 2` bytes).
  - Node and literal region lengths.
  - Stride scans (8/12/16 bytes) with tag sets and in-bounds edge rates.
- Persisted these observations via `analyze.py` and `out/summary.json`, with narrative in `Notes.md`.

**Upcoming**

- None for this section; baseline ingestion is considered stable.

---

## 2. Synthetic SBPL variants

Create small SBPL profiles that differ by one idea at a time, compile them, and compare their blobs.

**Done**

- Added a family of variants under `sb/`:
  - Baseline `file-read*` profile.
  - Subpath-only and dual-subpath profiles.
  - Literal+subpath mixes and multi-literal require-any/require-all shapes.
  - Later probes combining mach-lookup with subpath/literal to stress the layout.
- Compiled all variants using `sandbox_compile_string` in `analyze.py`.
- For each variant, recorded blob length, op_count, section lengths (op_table, nodes, literals), and stride/tail statistics into `out/summary.json`.

**Upcoming**

- Only add new SBPL variants if new structural hypotheses require additional shapes; prefer reusing this set where possible.

---

## 3. Stride and tail behavior

**Done**

- Treated the node region as fixed-size records at strides 8/12/16 for each variant and computed:
  - full-record counts and remainders,
  - distinct tags per stride,
  - in-bounds edge counts.
- Inspected the last few stride-aligned records and remainder bytes (e.g., v1 vs v4) to identify “tail-only” structure.
- Established that:
  - no stride yields a remainder-free node region,
  - stride 12 gives a clean front tag set, but tails carry extra records with odd edges (e.g., 3584) and non-zero remainders.

**Upcoming**

- Derive a consistent variable-size or mixed-stride model for the tail region, or explicitly document that no such simple model fits current data.

---

## 4. Literal pools, field2, and node fields

Hypothesis: node records reference the literal/regex pool via small indices or IDs, but the exposed fields may encode filter/branch keys more than literal offsets.

**Done**

- Inspected literal/regex pools to confirm expected strings across variants (e.g., `/tmp/foo`, `/tmp/bar`, `/etc/hosts`).
- Compared node regions for key variant pairs:
  - v1 vs v2 (same filter, different literal content) → node bytes identical; only literal tail changes.
  - v1 vs v4 (one vs two subpaths) → shared node prefix with extra tail nodes in v4.
  - v0 vs v5 (baseline vs literal+subpath) → only a small set of node records differ while the literal pool grows.
- Used extended probes (literal-only and mach+literal/subpath mixes) plus the shared decoder to observe stable field2 sets {0,3,4,5,6} across these variants and to confirm:
  - field2 behaves like a small key correlated with filter presence/branching rather than literal content or byte offsets.

**Upcoming**

- Use decoder-backed summaries and shared tag layouts to:
  - identify which node fields carry literal indices versus filter/branch keys,
  - clarify how literal references are represented (direct indices vs indirect tables),
  - tie specific field2 values to SBPL-level constructs in cooperation with the `field2-filters` and `probe-op-structure` experiments.

---

## 5. Op-table anchoring

The op-table is the bridge from Operations to node entrypoints; even without full node decoding, it constrains how many entrypoints exist and how they move with `op_count`.

**Done**

- Extracted op-table entries for each variant using the 0x10 + `op_count` heuristic and persisted them as `op_entries` in `out/summary.json`.
- Observed:
  - Uniform buckets for small unfiltered profiles (e.g., `[4,…]` vs `[5,…]`),
  - Non-uniform patterns such as `[6,6,6,6,6,6,5]` in mixed mach+filtered-read variants.
- Used these patterns as structural fingerprints to coordinate with the `op-table-operation` experiment.

**Upcoming**

- Treat non-uniform op-table patterns as structural hints and refine their interpretation using vocab-aligned results from `op-table-operation` and `op-table-vocab-alignment`.

---

## 6. Tooling and artifacts

**Done**

- Implemented `analyze.py` to:
  - compile all `sb/*.sb` into `sb/build/*.sb.bin`,
  - slice blobs into sections,
  - run stride/tail analysis,
  - call the shared decoder to capture `node_count`, tag counts, op_table offsets, literals, and section lengths,
  - write `out/summary.json` for use by other experiments.
- Ensured `Notes.md` references `analyze.py`, `out/summary.json`, and key observations.

**Upcoming**

- Keep `analyze.py` and `out/summary.json` aligned with decoder evolution and shared mapping artifacts, without changing the core “shape” of the experiment.

---

## 7. Remaining questions and follow-on work

These items remain open and are the natural next steps for future work. They should be tackled in combination with downstream experiments (field2 mapping, tag-layout decode, op-table alignment) rather than in isolation.

**Done (setup for follow-on work)**

- Integrated the shared decoder into the analysis pipeline so that node/tag counts, op_table offsets, and literal strings are available alongside stride stats.
- Added and studied a family of literal- and mach-heavy probes (two/three/four/five/six/seven+ literal require-any/all variants, mach+literal, mach+subpath), confirming:
  - field2 stability across literal content changes,
  - branch-marker behavior (e.g., field2=0 appearance/disappearance) as literal counts vary,
  - tail-word patterns that change with literal counts and compilation mode.

**Upcoming (conceptual)**

- Literal index mapping:
  - Use decoder-backed summaries and shared tag layouts to determine which fields, if any, encode literal-table indices versus purely filter/branch keys.
- Filter key location:
  - With decoder output and vocab in hand, look for stable vs changing node fields across profiles that add/remove specific filters (subpath, literal, require-any/all) and propose candidate fields for filter key codes.
- Tail layout:
  - Use decoder node and tag accounting to distinguish “front” vs “tail” regions and attempt a per-tag or per-region size model for tails; document any per-tag size patterns that emerge.
- Per-op segmentation:
  - Once op-table entrypoints can be traversed more confidently, run small graph walks from each entry to characterize reachable tags/literals per bucket, then feed that structure into vocab-aligned experiments.

