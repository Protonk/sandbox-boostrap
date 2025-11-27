# Node Layout Experiment – Research Report (macOS 14.4.1)

This report summarizes a first-pass investigation into the “modern” Seatbelt profile node layout on a Sonoma host, using only locally compiled blobs and the shared ingestion helpers. It is intended as a standalone artifact: a reader with only the substrate and this directory should be able to understand what we tried, what we learned, and what remains open.

## 1. Motivation and learning objectives

The synthetic textbook treats compiled sandbox profiles as PolicyGraphs: arrays of nodes and edges that encode operations, filters, and decisions. For the static-format and vocabulary/mapping stories to be more than schematic, we want a concrete, empirically grounded view of how those nodes are laid out in current macOS profile blobs.

Specifically, this experiment aimed to:

- Confirm that the shared ingestion helpers can reliably slice modern blobs into:
  - a preamble and operation pointer table,
  - a node region,
  - a literal/regex pool.
- Explore whether the node region can be treated as fixed-size records (stride-based decoding), and, if so, what stride and tag patterns look plausible.
- Understand how simple SBPL changes (adding filters, changing literals, mixing filter types) perturb the node region and literal pool.
- Produce reusable artifacts (SBPL variants, blobs, JSON summaries) that later work can use to refine layout and vocab hypotheses.

We deliberately did **not** try to fully reverse-engineer the modern node format; the goal was to get a solid, reproducible footing and to identify what remains stubbornly opaque.

## 2. Setup and tools

The experiment lives under `book/experiments/node-layout/`:

- `Plan.md` – current plan/checklist with completed steps and open items.
- `Notes.md` – dated running notes, including a narrative section.
- `sb/` – tiny SBPL variants used as probes.
- `analyze.py` – a small Python tool to compile all SBPL variants via `libsandbox`, slice the resulting blobs using `profile_ingestion.py`, and emit structured summaries.
- `out/summary.json` – machine-readable summaries for each variant.

The analyzer (`analyze.py`) is intentionally shallow:

- It uses `libsandbox`’s `sandbox_compile_string` to compile each `sb/*.sb` into `sb/build/*.sb.bin`.
- It passes each blob through `profile_ingestion.py` to get:
  - an approximate header (`format_variant`, `operation_count`, raw length),
  - section slices: op-table, nodes, literal/regex pool.
- It computes stride-based stats over the node region for strides 8/12/16:
  - record count, remainder, tag values (byte0), and how many interpreted edges stay within bounds.
- It records the last few stride-aligned node records and any trailing bytes (“tail”) at stride 12.
- It extracts op-table entrypoints (u16 indices) from the preamble.

All of this is written to `out/summary.json` so later tools or humans can pick up without rerunning the compilations.

## 3. Baseline: `sample.sb.bin`

We started from `book/examples/sb/sample.sb`:

```scheme
(version 1)
(deny default)

; allow basic runtime and library access
(allow process*)
(allow file-read* (subpath "/System"))
(allow file-read* (subpath "/usr"))
(allow file-read* (subpath "/dev"))

; demo paths
(allow file-read* (subpath "/tmp/sb-demo"))
(allow file-write* (require-all
                     (subpath "/tmp/sb-demo")
                     (require-not (vnode-type SYMLINK))))

; explicit deny to illustrate literal filters
(deny file-read* (literal "/etc/hosts"))
```

Compiled via the existing `compile_sample.py`, `sample.sb.bin` was ingested with `profile_ingestion.py`. The heuristic split yielded:

- a 16-byte preamble,
- a small op-table region,
- a node region of ~395 bytes,
- a literal/regex tail (~154 bytes) containing the expected strings (`/etc/hosts`, `usr`, `dev`, `system`, `/tmp/sb-demo`).

Quick stride scans (8/12/16) over the node region showed:

- all strides produced reasonable tag sets and edges mostly in-bounds (interpreting two u16 “edges” per record),
- stride=12 gave a particularly tidy tag distribution in the front of the array and fewer apparent anomalies, making it a reasonable working hypothesis for the *front* of the node region.

At this point we had a consistent picture: op-table, node bytes, literal tail. The question became how much of that node region we could align with SBPL concepts.

## 4. Synthetic SBPL variants

To explore how SBPL structure influences the compiled graph, we created a small family of SBPL profiles under `sb/`:

- `v0_baseline.sb` – allow `file-read*` only.
- `v1_subpath_foo.sb` – allow `file-read*` with `(subpath "/tmp/foo")`.
- `v2_subpath_bar.sb` – same as v1 but `(subpath "/tmp/bar")`.
- `v3_two_filters.sb` – `(require-all (subpath "/tmp/foo") (subpath "/dev"))` on `file-read*`.
- `v4_any_two_literals.sb` – `(require-any (subpath "/tmp/foo") (subpath "/tmp/bar"))`.
- `v5_literal_and_subpath.sb` – `(require-all (literal "/etc/hosts") (subpath "/tmp/foo"))` on `file-read*`.

Using `analyze.py` and `sandbox_compile_string`, we compiled each into a blob and recorded:

- blob length and `operation_count`,
- section lengths (op_table, nodes, literals),
- stride stats and tail records,
- op-table entrypoints.

A few key numbers from `summary.json`:

- v0: len 440, ops=5, nodes=387, literals=27.
- v1/v2: len 467, ops=6, nodes=365, literals=74.
- v3: len 440, ops=5, nodes=387, literals=27.
- v4: len 481, ops=6, nodes=403, literals=50.
- v5: len 440, ops=5, nodes=387, literals=27.

The structural trends:

- Adding a `subpath` filter (v1 vs v0) increases `operation_count`, shrinks the node region slightly, and expands the literal pool.
- Changing the literal content (v1 vs v2) leaves node bytes identical but changes the literal pool.
- Adding a second subpath via `require-any` (v4 vs v1) increases node and literal sizes; the shared prefix of the node region is identical, and new records appear in the tail.
- Adding a `literal` filter (v5 vs v0) keeps `operation_count` at 5, changes only a couple of node records, and grows the literal pool to include `/etc/hosts`.

## 5. What stride-based analysis tells us

For each variant, we treated the node region as if it were composed of fixed-size records under strides 8, 12, and 16. For each stride we tracked:

- number of full records and remainder bytes,
- tag values (byte0 of each record),
- how many interpreted edges (two u16s per record) stayed within the node region.

The main takeaways:

- **No stride fully explains node lengths.** For all variants, node lengths leave non-zero remainders under 8/12/16; the tails never align perfectly.
- **Stride=12 is a good front approximation.** In the front of the node array, stride=12 yields a small set of tags and edges that mostly stay in-bounds. This suggests some internal regularity, even if the tail uses a different encoding or includes trailers.
- **Tails are messy.** The last few stride-12 “records” in v4 (two-subpath variant) include:
  - a node with tag 5 and edges (5,4), lit=0,
  - a node with tag 0 and edges (1,4), lit=5,
  - a node with tag 4 and edges (5,3584), lit=1,
  plus a partial tail of 7 bytes. The edge value 3584 is clearly out-of-bounds, so some of these fields are not pure node indices, or the stride assumption breaks down in the tail.

Our current conclusion is that stride=12 is useful for *summarizing* the front of the node region, but the actual node layout is not a simple fixed-stride array across the entire section.

## 6. Literal pools vs node fields

One core question was how modern blobs tie filter nodes back to literal/regex data. The variants were designed to stress that:

- v1 vs v2: `(subpath "/tmp/foo")` vs `(subpath "/tmp/bar")`.
  - Node regions are byte-for-byte identical.
  - Literal pools differ and contain the expected strings.
- v1 vs v4: one subpath vs `require-any` of two subpaths.
  - Node prefixes are identical.
  - Extra nodes appear only at the end of v4’s node region.
  - Literal pool expands to hold both `/tmp/foo` and `/tmp/bar`.
- v0 vs v5: baseline vs `(literal "/etc/hosts")` + subpath.
  - Node regions have the same length; only two records differ.
  - Literal pool grows to include `/etc/hosts`.

Under the stride-12 view, we treated bytes 6–7 of each record as a candidate “literal index” field. That field changes in some variants (especially where the number of filters changes), but crucially:

- Changing literal content alone (foo→bar) does not change the suspect field in the shared prefix.
- Adding a second literal in `require-any` produces new nodes in the tail, but the shared prefix remains stable.

This strongly suggests that:

- Literal strings are clearly present in the tail, but
- Node records likely refer to them via compact IDs or through a secondary indirection, rather than by raw offsets into the literal pool, and
- For these tiny profiles, many of the interesting literal-related nodes live in the tail segments we do not yet decode cleanly.

We have not yet found a simple, stride-friendly field that we can confidently label “literal index.”

## 7. Op-table entrypoints

The operation pointer table is the documented bridge from operations to graph entry nodes. Using the heuristic that it starts at byte 0x10 and contains `operation_count` u16 indices, we first extracted op-table entries for the single-op and single-filter variants:

- v0 / v5 (ops=5): op_entries `[4,4,4,4,4]`.
- v1 / v2 / v4 (ops=6): op_entries `[5,5,5,5,5,5]`.

In other words, in these initial tiny synthetic profiles, every operation points to the same entry index. This tells us:

- The op-table is present and structured, but
- For these cases it does not help segment the node array per operation, because all ops share the same entrypoint.

Later mixed-op probes (see §10) introduce profiles with `op_count=7` and non-uniform entries `[6,6,6,6,6,6,5]`, giving the first evidence of more than one entry index in use but still no clear mapping from individual operations to unique entrypoints.

## 8. Artifacts produced

The experiment left behind several reusable artifacts:

- **SBPL variants** in `book/experiments/node-layout/sb/`:
  - Minimal profiles that isolate specific SBPL features: subpaths, multiple subpaths, literal filters.
- **Compiled blobs** in `book/experiments/node-layout/sb/build/`:
  - Modern `.sb.bin` blobs that can be re-sliced with updated ingestion code.
- **Analyzer**: `book/experiments/node-layout/analyze.py`:
  - Single entrypoint to compile all variants and emit structured summaries.
- **Structured summaries**: `book/experiments/node-layout/out/summary.json`:
  - Per-variant JSON objects with:
    - blob length, `format_variant`, `operation_count`,
    - op-table entrypoints,
    - section lengths (op_table, nodes, literals),
    - stride stats for 8/12/16,
    - tail records and remainder bytes at stride 12.
- **Narrative and plan**:
  - `Plan.md` – checklist of completed steps and explicitly open questions.
  - `Notes.md` – dated notes plus a narrative section summarizing the experiment.

These artifacts decouple the heavy work (compilation, slicing) from later analysis: a future agent can start from `summary.json` and the blobs without having to re-run everything from scratch.

## 9. Where we stand (and what’s still open)

At this stage we have:

- A consistent heuristic for slicing modern profile blobs into op-table, nodes, and literal pool.
- Evidence that:
  - adding or removing filters changes the node region and literal pool in predictable ways,
  - changing literal content (foo→bar) affects only the literal pool, not the node bytes in shared prefixes,
  - tails of the node region contain additional structure that does not fit a simple fixed stride and may encode literal- or filter-specific details.
- A reusable analyzer and structured summaries for all the synthetic variants.

We **do not yet** have:

- A trustworthy mapping from node fields to literal indices or filter key codes.
- A robust node layout model that explains tails (and odd edge values) as well as the front of the node region.
- More than very coarse per-operation segmentation of the graph from op-table entries: mixed-op profiles show at most two distinct entry indices shared across several operations, and we still lack a vocabulary-aware mapping from operations to entrypoints.

In terms of the textbook’s goals, this is still useful:

- It confirms that modern blobs retain the broad structure described in the substrate (headers, op-tables, nodes, literal pools).
- It grounds the claim that literal pools and op-tables are present and can be sliced without full reverse engineering.
- It highlights exactly where our knowledge runs out: the fine structure of modern node formats, and the precise mapping of filters and literals back to SBPL.

Future work can build on this by:

- Designing additional profiles where different operations have visibly different policies, building on the mixed-op probes in §10, to further refine op-table entrypoint mapping.
- Extending `analyze.py` or related tools to experiment with variable-length node parsing and to correlate node fields with literal pool indices more aggressively.
- Feeding these artifacts into a more systematic reverse-engineering pass that can be versioned and tied back into the substrate as a new static-format annex.

## 10. Mixed-op probes and first op-table divergence

Follow-on probes added mixed operations with distinct filters to stress per-op entrypoints:

- `v8_read_write_dual_subpath`: `file-read*` with `(subpath "/tmp/foo")`, `file-write*` with `(subpath "/tmp/bar")`.
- `v9_read_subpath_mach_name`: `file-read*` with `(subpath "/tmp/foo")`, `mach-lookup` with `(global-name "com.apple.cfprefsd.agent")`.
- `v10_read_literal_write_subpath`: `file-read*` with `(literal "/etc/hosts")`, `file-write*` with `(subpath "/tmp/foo")`.

Analyzer enhancements now emit full stride=12 record dumps, per-tag counts, and ASCII literal runs; the refreshed `summary.json` captures these.

Findings:

- These profiles bump `op_count` to 7 and, for the first time, op-table entries are non-uniform: `[6, 6, 6, 6, 6, 6, 5]`. This suggests at least two distinct entry indices in play, though operation→index mapping is still unknown.
- Node tag sets now include tag6; early stride=12 records carry the main differences across variants (indices ~3–5, 14), with tag6/tag3 swaps and lit fields toggling 3↔6 alongside edge/extra changes (`03000600` vs `06000600`).
- Node lengths vary slightly (v8/v9: 32 records + 2-byte remainder; v10: 31 records + 11-byte remainder), hinting at structural shifts when a `literal` filter is involved.
- Literal pools now show prefixed strings: `G/tmp/foo`, `G/tmp/bar`, `Wcom.apple.cfprefsd.agent`, `I/etc/hosts`, reinforcing that the pool stores a class/type marker alongside the payload.

Still open:

- Which operation maps to the lone `5` op-table entry.
- Whether tag6 corresponds to a specific filter class or branching construct, and how its size interacts with the tail remainders.
- How to parse the tail beyond fixed stride so these per-op differences can be tied to concrete filter keys and literal references.
