# Node Layout Experiment Plan (Sonoma host)

Goal: recover enough of the modern compiled profile node layout to say something concrete about node tags, edges, and (eventually) filter keys, using only local artifacts. 

---

## 1. Baseline ingestion and heuristics

- [x] Use the shared ingestion helpers (`book/graph/concepts/validation/profile_ingestion.py`) to:
  - [x] Classify `book/examples/sb/build/sample.sb.bin` as a modern graph-based blob.
  - [x] Slice it into:
    - a small preamble/op-table area,
    - a “nodes” region,
    - a literal/regex tail with human-readable strings.
- [x] For the baseline blob, record:
  - [x] `operation_count` from the heuristic header.
  - [x] Approximate op-table length (`op_count * 2` bytes).
  - [x] Node region length and literal region length.
  - [x] A quick stride scan (8/12/16 bytes) that reports tag sets and whether interpreted edges stay in-bounds.
- [x] Persist these observations in:
  - [x] `book/experiments/node-layout/Notes.md` (running notes).
  - [x] `book/experiments/node-layout/analyze.py` + `out/summary.json` (machine-readable summary).

Result so far:
- `sample.sb.bin` consistently slices into:
  - 0x10-byte preamble,
  - op-table (`operation_count` u16 entries),
  - node bytes,
  - literal tail (containing `/etc/hosts`, `usr`, `dev`, `system`, `/tmp/sb-demo`).
- Stride=12 gives a small, stable tag set in the front of the node region; tails have non-zero remainders.

---

## 2. Synthetic SBPL variants

Create small SBPL profiles that differ by one idea at a time, compile them, and compare their blobs.

- [x] Add variants under `book/experiments/node-layout/sb/`:
  - [x] `v0_baseline.sb`: allow `file-read*` only.
  - [x] `v1_subpath_foo.sb`: allow `file-read*` with `(subpath "/tmp/foo")`.
  - [x] `v2_subpath_bar.sb`: same but with `(subpath "/tmp/bar")`.
  - [x] `v3_two_filters.sb`: `(require-all (subpath "/tmp/foo") (subpath "/dev"))` on `file-read*`.
  - [x] `v4_any_two_literals.sb`: `(require-any (subpath "/tmp/foo") (subpath "/tmp/bar"))`.
  - [x] `v5_literal_and_subpath.sb`: `(require-all (literal "/etc/hosts") (subpath "/tmp/foo"))`.
- [x] Compile all variants using `sandbox_compile_string` and the helper in `analyze.py`.
- [x] For each variant, record:
  - [x] Blob length, op_count.
  - [x] Section lengths (op_table, nodes, literals).
  - [x] Stride stats and tail records in `out/summary.json`.

Key observations (captured in `Notes.md` and `out/summary.json`):
- Adding a single `subpath` filter (v1 vs v0) increases op_count and changes node/literal sizes.
- Changing `/tmp/foo` → `/tmp/bar` (v1 vs v2) leaves node bytes identical but alters the literal pool.
- Adding a second subpath in `require-any` (v4 vs v1) lengthens the node region; shared prefix is identical, extras live in the tail.
- Adding a `literal` filter (v5) changes a small slice of nodes (vs baseline) and grows the literal pool without changing op_count.

---

## 3. Stride and tail behavior

- [x] For each variant, treat the node region as a sequence of fixed-size records and compute stride stats for 8/12/16.
  - [x] Count full records and remainders.
  - [x] Track distinct tags per stride.
  - [x] Count how many interpreted edges stay in-bounds (crude sanity check).
- [x] Inspect the last few stride-aligned records and remainder bytes:
  - [x] For v1 vs v4, list records that exist only in v4’s tail.

What we now know:
- For all variants, no tested stride yields “no remainder”; node lengths always leave trailing bytes.
- Stride=12 gives a clean tag set in the front, but tails show:
  - additional records with odd edges (e.g., 3584) and non-zero remainders,
  - suggesting that the actual node layout is not a simple fixed-stride array across the entire region.
- v1 vs v4 tails: extra v4 records carry literal-ish indices (0,5,1) and odd edges; they are clearly additional structure, but their exact semantics remain unclear.

Open check:
- [ ] Derive a consistent variable-size or mixed-stride model for the tail. (Current brute-force attempt at tag→{8,12,16} mapping failed.)

---

## 4. Literal pools and node fields

Hypothesis: node records reference the literal/regex pool via small indices or IDs, but our current fields may not be literal offsets.

- [x] Inspect literal/regex pools:
  - [x] Confirm that v1/v2/v4 pools contain the expected path strings.
  - [x] Confirm that v0/v3/v5 pools do not have `/tmp/foo`/`/tmp/bar` (or only have `/etc/hosts` where expected).
- [x] Compare node regions across:
  - [x] v1 vs v2 (same filter, different literal content).
  - [x] v1 vs v4 (one vs two subpaths).
  - [x] v0 vs v5 (baseline vs literal+subpath).

Findings:
- v1 vs v2: node regions are bit-identical; only literal pools differ → changing literal content alone does not touch the front of the node region.
- v1 vs v4: node prefixes identical; extra nodes appear only at the end of v4’s node region, and the literal pool grows to include both `/tmp/foo` and `/tmp/bar`.
- v0 vs v5: only two node records differ, while literal pool grows to include `/etc/hosts` as expected.

Open checks:
- [ ] Identify which node field (if any) carries a literal index:
  - Current candidate (bytes 6–7 under stride=12) behaves like a small ID but does not change with foo→bar.
- [ ] Determine whether literal references in modern blobs are indirect (e.g., node→secondary table→literal pool).

---

## 5. Op-table anchoring

The op-table is the bridge from operations to node entrypoints. Even if we do not fully decode nodes, we want to know how many entrypoints there are and how they move with op_count.

- [x] Extract op-table entries for each variant:
  - [x] Use the heuristic that the table starts at byte 0x10 and contains `op_count` u16 indices.
  - [x] Persist them in `out/summary.json` as `op_entries`.

Observations:
- v0/v5 (op_count=5) both have op entries `[4,4,4,4,4]`.
- v1/v2/v4 (op_count=6) have op entries `[5,5,5,5,5,5]`.
- This suggests that on these initial tiny profiles, all operations share the same entry index; op-table entries do not help segment nodes per operation yet. Later mixed-op probes (`v6`–`v10`) show the first non-uniform op-table entries but still do not give a clean mapping from individual operations to unique entrypoints.

Open check:
- [x] Find a profile where operations differ meaningfully (e.g., `file-read*` vs `file-write*`) and verify whether op-table entries diverge. (Achieved with mixed-op variants `v8`–`v10`, which show op-table entries `[6,6,6,6,6,6,5]`; mapping back to specific operations remains unresolved.)

---

## 6. Tooling and artifacts

- [x] Persist a reusable analyzer:
  - [x] `book/experiments/node-layout/analyze.py` compiles all `sb/*.sb`, writes `sb/build/*.sb.bin`, and emits `out/summary.json` with:
    - blob length, format_variant, op_count, op_entries,
    - section lengths (op_table, nodes, literals),
    - stride stats for 8/12/16,
    - tail records and remainder bytes for stride 12.
- [x] Ensure `Notes.md` captures the narrative and references the analyzer and summary.

Usage:
- From the repo root:
  - `PYTHONPATH=. python3 book/experiments/node-layout/analyze.py`
  - Inspect `book/experiments/node-layout/out/summary.json` for structured data.

---

## 7. What remains open

These items are explicitly *not* solved yet; they are the next frontier for future work:

- [x] **Decoder integration:** Update `analyze.py` to reuse `book.graph.concepts.validation.decoder.decode_profile_dict` so that `out/summary.json` includes shared fields (`node_count`, `tag_counts`, `op_table_offset`, `literal_strings`) in addition to existing stride stats.
- [ ] **Literal index mapping:** Use decoder-backed summaries to re-run foo→bar and multi-literal comparisons and test which node fields correlate with literal-table indices versus content changes.
- [ ] **Filter key location:** With decoder output in hand, search for stable vs changing node fields across profiles that add/remove specific filters (subpath, literal, require-any/all), and propose candidate fields for filter key codes.
- [ ] **Tail layout:** Use decoder’s node and tag accounting to distinguish “front” vs “tail” regions (where new nodes appear compared to a baseline), and attempt a per-tag or per-region size model for the tail; document any per-tag size patterns that emerge.
- [ ] **Per-op segmentation:** Once op-table entrypoints can be traversed via decoder output, run small graph walks from each entry to characterize reachable `tag_counts` and literals per operation bucket; this should give a structural (ID-agnostic) segmentation that can later be tied to vocab IDs by the op-table experiments.

Progress update (2025-11-30):
- [x] **Decoder integration:** `analyze.py` now calls `book.graph.concepts.validation.decoder.decode_profile_dict` and records decoder fields (`node_count`, decoder `tag_counts`, `op_table_offset`, decoder literals, section lengths) in `out/summary.json`. The decoder view matches the earlier stride heuristics (op_table_offset=16, node counts in the low 30s).
- [ ] **Literal index mapping:** Started decoder-backed comparisons (foo→bar identical nodes; second subpath adds a single tail node with field2=0; literal+subpath reshapes many nodes). Field at offsets 6–7 (decoder `fields[2]`) shifts with filter presence but not literal content; still need to tie values to literal pool ordering.
- [ ] **Filter key location:** Decoder field2 values now clustered by filter/operation: baseline {3,4}; subpath {3,4,5}; mach {4,5}; dual subpath introduces {0}; mixed filtered/mach adds {0,5,6}. Candidate: field2 is a filter/literal key, but mapping to names remains open.
- [ ] **Tail layout:** Distinguish “front” vs “tail” regions using decoder node counts and tag patterns; attempt a per-tag or per-region size model for the tail.
- [ ] **Per-op segmentation:** Build small graph walks from op-table entrypoints using decoder node lists to characterize reachable tags/literals per bucket; align those with op-table-operation signatures once vocab IDs exist.
- [ ] **Literal pool vs field2:** Literal byte offsets differ across profiles (`/tmp/foo` at 57 vs 45/71, etc.) while field2 sets stay stable; preliminary conclusion is that field2 values (0/3/4/5/6) are small keys for filter presence/branching, not literal offsets. Need targeted deltas to map each value to an SBPL construct.
- [ ] **New literal probes:** Added `v20_read_literal` and `v21_two_literals_require_any` to isolate literal-only behavior; field2=0 now shows up as the “second branch” in require-any over literals, reinforcing the branch-key hypothesis. Still need a minimal mach+literal-only probe to see if field2=6 appears without subpath/multi-branching.

Progress update (2025-12-01):
- [x] **Mach + literal probes:** Added `v22_mach_literal` and `v23_mach_two_literals_require_any`; both yield op-table `[6,…,5]`, tag counts {0:1,5:5,6:25}, and field2 histogram {6:17,5:12,4:1,0:1}, matching the mach+subpath variant. Decoder `nodes` are identical across these profiles; differences are confined to node-region remainders and literal pools.
- [ ] **Literal index mapping:** Still open; mach+literal vs mach+subpath shows field2 stability across filter flavor and even require-any over literals, suggesting field2 keys are filter/branch identifiers rather than literal indices.
- [ ] **Tail layout:** New probes show tail/remainder bytes shift with filter flavor even when decoded nodes stay fixed; still need a model for what those trailing bytes represent.

Progress update (2025-12-01, later):
- [x] **Three-literal require-any probe:** Added `v24_three_literals_require_any`; field2 histogram drops the branch marker (no `field2=0`), node_count shrinks to 30, and the extra `tag5` node seen in two-literal require-any disappears. Suggests require-any compiles differently once >2 literals are present.
- [ ] **Tail layout:** Captured remainder hex deltas across matched-node profiles (`v9` vs `v22`, `v22` vs `v23`, `v21` vs `v24`); still need to interpret these bytes or correlate them with filters.

Progress update (2025-12-02):
- [x] **Four-literal require-any probes:** Added `v25` and `v26` (reordered). Decoder nodes stay identical to the three-literal case; field2 remains {3,4,5} with no `field2=0`, confirming the branch marker stays absent when ≥3 literals are present and insensitive to order.
- [x] **Require-all probes:** Added `v27`/`v28` (two vs four literals). Field2 collapses to {3,4}, op-table `[4,…]`, node_count=32, decoder literals empty; nodes identical across literal counts. Require-all does not expose branch markers or literal strings in the decoder output.
- [ ] **Tail layout:** Remainder bytes logged for require-any (len5 `0500050004` once ≥3 literals) and require-all (len3 `010003`). Still need a model for these tails.

Progress update (2025-12-02, later):
- [x] **Five/six-literal require-any probes:** Added `v29` (five literals) and `v30` (six literals). Field2 stays {3,4,5} for 5 literals; at 6 literals a single `field2=0` `tag5` node reappears (node_count=31) and the tail flips back to the two-literal pattern.
- [x] **Tail helper:** Logged tail words for require-any/all: require-any shows `[3584,1,4,5]` when there are exactly 2 or 6 literals (with `field2=0`), `[5,5,4]` for 3–5 literals; require-all tails stay `[1,3]`. Literal pool length scales with literal count even when decoder literals are empty.
- [ ] **Tail model:** Still need to interpret what these tail words represent (counts? pointers?) and why the branch marker toggles at 6 literals.

Progress update (2025-12-02, late):
- [x] **7+/require-any probes:** Added `v31` (seven literals) and `v32` (eight literals). Field2 stays {3,4,5,0}, node_count=31, op-table `[5,…]`, decoder nodes identical to the six-literal mode; tail remains `[3584,1,4,5]`. Branch marker persists for ≥6 literals.
- [ ] **Tail model:** Threshold behavior confirmed (2 and ≥6 vs 3–5 literals). Still open to decode meaning of `[3584,1,4,5]` vs `[5,5,4]`.

Even with these open boxes, the experiment has already produced reusable artifacts (SBPL variants, blobs, structured summaries) and a clearer picture of what can and cannot be inferred from modern graph blobs without deeper reverse engineering.
