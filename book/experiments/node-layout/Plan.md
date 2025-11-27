# Node Layout Experiment Plan (Sonoma host)

Goal: recover enough of the modern compiled profile node layout to say something concrete about node tags, edges, and (eventually) filter keys, using only local artifacts. This plan is written so a new agent with only `spine/` can replay the work.

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

- [ ] **Literal index mapping:** We still do not know exactly how nodes refer to the literal/regex pool in modern blobs. Controlled foo→bar and multi-literal variants show pool changes but not obvious node-field changes in shared prefixes.
- [ ] **Filter key location:** We have not yet identified which node field carries filter key codes as opposed to literal indices; tag and edge patterns alone are insufficient.
- [ ] **Tail layout:** Extra nodes and remainders at the tail do not fit a simple fixed stride; a better model (variable-size records, per-tag sizes, or a distinct tail encoding) is still to be derived.
- [ ] **Per-op segmentation:** Mixed-op profiles now show at least two distinct op-table entry indices, but we still lack a mapping from operation vocabulary IDs to those indices and a way to use them to cleanly segment the node array per operation.

Even with these open boxes, the experiment has already produced reusable artifacts (SBPL variants, blobs, structured summaries) and a clearer picture of what can and cannot be inferred from modern graph blobs without deeper reverse engineering.
