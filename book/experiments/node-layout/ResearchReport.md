# Node Layout Experiment – Research Report (Sonoma / macOS 14.4.1)

This document is a self-contained report for the **node-layout** experiment under `book/experiments/node-layout/`. It explains what we have done, what we know about modern Seatbelt PolicyGraph layout on this host, and what remains to be done. New agents should be able to read this file plus `Plan.md` and `Notes.md` to resume the work.

---

## 1. Purpose and context

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

## 2. Environment, tools, and artifacts

**Host / baseline**

- macOS 14.4.1 (23E224), Apple Silicon, SIP enabled.
- Profiles compiled locally via `libsandbox.dylib` on this host; results are host-specific but conceptually aligned with `SUBSTRATE_2025-frozen`.

**Directory contents**

- `Plan.md` – current checklist and open questions.
- `Notes.md` – dated running notes; useful for detailed provenance.
- `sb/` – SBPL variants used as probes.
- `sb/build/*.sb.bin` – compiled policy blobs (one per SBPL variant).
- `analyze.py` – main tooling for this experiment:
  - compiles `sb/*.sb` via `sandbox_compile_string`,
  - slices blobs with `book.graph.concepts.validation.profile_ingestion`,
  - calls `book.graph.concepts.validation.decoder.decode_profile_dict`,
  - emits `out/summary.json`.
- `out/summary.json` – machine-readable per-variant summary, including:
  - blob length, heuristic `operation_count`,
  - op-table section length and raw op-table entries,
  - node region length,
  - literal/regex pool length,
  - stride-based stats for the node region (8/12/16),
  - full stride=12 record dump (for historical reference),
  - literal strings extracted heuristically,
  - **decoder** snapshot:
    - `format_variant`,
    - `op_table_offset`,
    - `op_count`,
    - `node_count`,
    - decoder `tag_counts`,
    - decoder `literal_strings`,
    - decoder `sections` lengths.

**Shared tooling from `book/graph/concepts/validation`**

- `profile_ingestion.py` – slices blobs into:
  - 16‑byte preamble,
  - **Operation Pointer Table** bytes,
  - node region bytes,
  - literal/regex pool bytes.
- `decoder.py` – **heuristic modern-profile decoder** that:
  - guesses `op_count` from the preamble,
  - infers the op-table region,
  - treats nodes as 12‑byte records,
  - returns a JSON-friendly dict with:
    - per-node `tag` and `fields`,
    - `node_count`,
    - stringified `tag_counts`,
    - printable strings from the literal/regex pool.

These tools give us a consistent “slice + decode” view of modern profiles that we use in this experiment and others.

---

## 3. SBPL probes and compiled profiles

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

## 4. Structural layout of modern profiles

Across all variants on this host, we see the following structural invariants:

- A 16‑byte preamble, followed by:
  - an **Operation Pointer Table** (`op_count` 16‑bit entries),
  - a node region,
  - a literal/regex pool.
- `profile_ingestion` and the decoder agree on:
  - `op_table_offset = 16` bytes,
  - node and literal section lengths (with minor variations per profile).

The node region behaves like:

- a mostly-regular array of 12‑byte records (stride‑12) at the **front**,
- a more irregular **tail** where stride‑12 still works as an approximation, but:
  - there are remainders (non-multiple-of-12 lengths),
  - some interpreted “edges” go out of bounds,
  - additional structure appears (especially when metafilters or more complex combinations are present).

The decoder formalizes this view:

- Treats every 12‑byte chunk as a node:
  - first 2 bytes → `tag` (node type),
  - next 5 words → `fields` (opaque 16‑bit values),
  - exposes per-node hex plus `tag_counts`.
- Reports `node_count` in the low 30s for all variants:
  - `v0_baseline`: 32 nodes,
  - `v1_subpath_foo`: 30 nodes,
  - `v4_any_two_literals`: 31 nodes,
  - `v8_read_write_dual_subpath`, `v9_read_subpath_mach_name`, `v10_read_literal_write_subpath`: ~31–32 nodes.

We retain stride-based views in `summary.json` for historical comparison, but the decoder is the primary structural lens going forward.

---

## 5. Literal pools and content vs structure

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
  - Adding a single subpath (v1) vs baseline (v0) changes many nodes and reduces `node_count` (32→30).
  - Adding a second subpath under `require-any` (v4) adds exactly one new node at the **tail** (offset 360) without changing the shared prefix.
  - Adding a literal filter alongside a subpath (v5) reshapes many nodes, increasing `node_count` and changing the front of the array.

Literal byte offsets in the pool (as measured by naive substring search) vary per profile and do **not** line up with any simple node field; this strongly suggests an indirection rather than “node field = literal offset”.

---

## 6. Candidate node fields for filters and branches

The key structural observation from decoder output is that the **third 16‑bit field** in each node (bytes 6–7, `fields[2]`) changes in a way that tracks **filter presence and branching**, not literal content:

- **Baseline (`v0_baseline`)**:
  - `field2` values `{3, 4}`, with counts `{3:12, 4:20}`.
  - No literals in the decoder’s `literal_strings`.

- **Single subpath filter (`v1_subpath_foo` / `v2_subpath_bar`)**:
  - `field2` moves to `{3:1, 4:9, 5:20}`.
  - Decoder literals: `['G/tmp/foo']` or `['G/tmp/bar']`.
  - Node bytes are identical across foo→bar; `field2` reacts to the presence of a `subpath` Filter, not to which path is chosen.

- **Two subpaths under `require-any` (`v4_any_two_literals`)**:
  - `field2` counts `{0:1, 3:1, 4:9, 5:20}`.
  - A single new node at offset 360: `tag=5`, `fields=[5,4,0,0,0]` – the only node with `field2=0`.
  - Interpretation: `field2=0` marks the *second branch* of a `require-any` Metafilter; the rest of the graph shares the `field2` pattern with the single-subpath case.

- **Literal-only and literal-branch probes (`v20`, `v21`)**:
  - `v20_read_literal` (single literal on `file-read*`):
    - `field2` counts `{3:1, 4:9, 5:20}`,
    - decoder literals: `['I/etc/hosts']`.
    - No `field2=0` or `field2=6`; field2=5 behaves like “one filtered op” just as with subpath.
  - `v21_two_literals_require_any` (two literals under `require-any`):
    - `field2` counts `{0:1, 3:1, 4:9, 5:20}`,
    - adds exactly one `field2=0` node and one extra `tag5` node,
    - mirrors the dual-subpath `require-any` shape.
  - This strongly reinforces the idea that `field2=0` encodes “additional branch under require-any” independent of filter type (subpath vs literal).

- **Mach and operation-mix profiles**:
  - Mach-only (`v11_mach_only`) and mach+network/write (`v14`, `v18`, `v19`) cluster `field2` in `{4, 5}`, with decoder literals like `['Wcom.apple.cfprefsd.agent']`.
  - Write-only and network-only profiles stay at `{3, 4}` (no 5/0/6).
  - Mixed, tag6-heavy profiles (`v8_read_write_dual_subpath`, `v9_read_subpath_mach_name`, `v10_read_literal_write_subpath`) introduce `field2` values `{0, 3, 4, 5, 6}` with counts resembling `{0:1, 3:2, 4:1, 5:12, 6:15}` and many nodes of `tag6`.
  - Nodes with `field2=6` predominantly appear on `tag6` nodes, often at the front of the array and in the tail.
  - Mach + literal-only probes (`v22_mach_literal`, `v23_mach_two_literals_require_any`) land on the same pattern as `v9`: op-table `[6,…,5]`, tag counts {0:1,5:5,6:25}, `field2` histogram {6:17,5:12,4:1,0:1}. Decoder `nodes` are identical across `v22`/`v23`/`v9`; differences are confined to node-region remainders and literal pools. Require-any over literals under mach does not introduce new `field2` values beyond the existing {0,4,5,6}.
  - Three-literal require-any without mach (`v24_three_literals_require_any`) drops `field2=0` entirely (histogram {5:20,4:9,3:1}, node_count=30) and removes the extra `tag5` node seen in the two-literal require-any (`v21`). This suggests `require-any` may compile differently once there are more than two branches (balanced/folded) rather than emitting an explicit “second branch” marker.
  - Four-literal require-any (v25/v26, reordered) keeps the same pattern as v24: field2 {5:20,4:9,3:1}, node_count=30, op-table `[5,…]`, decoder nodes identical across orderings. Literal order and count ≥3 do not reintroduce `field2=0`.
  - Five-literal require-any (v29) remains identical to v25/v26 (field2 {5,4,3}, node_count=30, no `field2=0`); six-literal require-any (v30) reintroduces a single `field2=0` `tag5` node (node_count=31) and matches the earlier two-literal branch-marker pattern. Tail words flip alongside this change (see below).
  - Seven- and eight-literal require-any (v31/v32) stay in the six-literal mode: field2 {5,4,3,0}, node_count=31, op-table `[5,…]`, decoder nodes identical to v30; branch marker persists and tails remain in the “long” pattern.
  - Require-all over literals (v27/v28) reverts to the baseline-like field2 set {3,4} with op-table `[4,…]`, node_count=32, and decoder literal_strings empty despite a non-zero literal pool. Two vs four literals produce identical decoded nodes and tails.

**Working hypothesis**

- The third word (`fields[2]`) is a **compact key** that:
  - distinguishes “plain” nodes (values 3/4),
  - encodes the presence of a single filter on an operation (value 5),
  - marks extra branches created by `require-any` (value 0),
  - and, in more complex mixes, may mark a separate family of filter/operation branches (value 6) associated with tag6-heavy regions.
- It does **not** directly encode literal pool offsets; literal byte positions vary across profiles while the `field2` sets stay stable for a given filter structure.

We still lack a mapping from these numeric keys to the **Filter Vocabulary Map**, but we now have repeatable structural differences tied to precise SBPL edits.

---

## 7. Mixed operations and op-table behavior (high-level tie-in)

Although this experiment is node-centric, some observations intersect with the **Operation Pointer Table**:

- For most small profiles, op-table entries are **uniform**:
  - baseline / read / write / network-only → entries `[4,4,4,4,4]`,
  - mach-only and “mach in the mix” without extra filters → `[5,5,5,5,5,5]`.
- Profiles that combine mach with filtered reads and bump `operation_count` to 7 (e.g., `v8`, `v9`, `v10`) show **non-uniform** op-tables: `[6,6,6,6,6,6,5]`.
  - These also introduce tag6-heavy node regions and the expanded `field2` set including value 6.
- At this stage, we treat op-table entries (4/5/6) as **opaque buckets**:
  - 4: “unfiltered” operations (read/write/network and baseline),
  - 5: “filtered or mach-involved” graphs in simpler cases,
  - 6: additional entrypoints that arise in more complex profiles (mach + filtered read).

The **op-table vs operation** experiment builds on this; here, we simply record the structural correlation between tag6, `field2` patterns, and op-table buckets.

---

## 8. What we do **not** know yet

Despite the progress above, several important pieces remain unknown or only loosely constrained:

1. **Exact node type semantics**
   - We treat `tag` values (0, 1, 2, 3, 4, 5, 6, …) as opaque node-type codes.
   - We do not yet know which tags correspond to specific Filter tests, Metafilter combinators, or Decision nodes, only that certain tags (e.g., 6) emerge in complex, filtered profiles.

2. **Precise filter key mapping**
   - While `fields[2]` is a strong candidate for a “filter key” / branch key, we cannot yet tie specific numeric values (0/3/4/5/6) to particular Filter vocabulary entries (e.g., `subpath`, `literal`, `global-name`, etc.).
   - We also do not know whether `fields[2]` points directly into a Filter table or into a more complex indirection.

3. **Tail layout and mixed node sizes**
   - The front of the node region behaves nicely under stride‑12, but the tail regularly exhibits:
     - non-multiple-of-12 lengths,
     - odd edge values,
     - nodes whose semantics are unclear (especially with field2=0/6 and remainders).
   - Earlier brute-force attempts to assign per-tag sizes (8/12/16) to explain the tails did not converge.
   - Recent mach/literal swaps show identical decoded nodes while tail bytes change (e.g., `v9` vs `v22` remainders `0600000e01` vs `010005000600000e010005`; `v22` vs `v23` swap `010005000600000e010005` vs `06`; `v21` vs `v24` shift `000e0100040005` vs `0500050004`). Tail bytes likely carry filter-specific data the current decoder ignores.
   - Require-any tails oscillate between two word patterns: `[3584,1,4,5]` (hex `000e0100040005`) when there are exactly 2 or ≥6 literals (and a `field2=0` branch node), and `[5,5,4]` (hex `0500050004`) for 3–5 literals (no branch node). Require-all tails stay at `[1,3]` (hex `010003`) regardless of literal count. Literal pool lengths scale with literal count even when decoder literal_strings stay empty (require-all).

4. **Per-operation segmentation**
   - We know that multiple Operations often share the same op-table entry in small profiles (especially when op-table entries are uniform).
   - We do not yet have a clean way, within this experiment alone, to walk from a specific Operation ID to a distinct region of the node graph and say “these nodes belong to `file-read*` vs `mach-lookup`”.

5. **Connection to vocabulary maps**
   - There is still no Operation or Filter Vocabulary Map (`ops.json`, `filters.json`) available for this host.
   - We intentionally avoid labeling any numeric tag or field value with a human-readable Filter or Operation name; that will require canonical vocabulary artifacts and possibly runtime traces.

---

## 9. Recommended next steps (for future agents)

The `Plan.md` file lists detailed tasks; this section highlights the most impactful next steps for a new agent picking up the experiment.

1. **Tighten field2 ↔ SBPL construct hypotheses**
   - Design additional single-change SBPL variants that:
     - add/remove **exactly one** filter of a given type (`subpath`, `literal`, `global-name`, etc.),
     - swap `require-any` and `require-all`,
     - move the same filter between different operations.
   - For each new variant:
     - re-run `analyze.py`,
     - compare decoder `nodes` and `field2` histograms to the nearest baseline,
     - document how `field2` changes.
   - Goal: reach a table of the form “field2 value X consistently appears when construct Y is present” without claiming more than the data supports.

2. **Front vs tail characterization**
   - For a small subset of variants (baseline, single subpath, dual subpath, dual literal, one tag6-heavy mix):
     - choose a cutoff index that separates “front” from “tail” (for example, last index shared with baseline vs new nodes),
     - record tag distributions and field patterns separately for front and tail,
     - look for patterns such as “require-any branch nodes only appear in the tail” or “tag6 nodes cluster at the front”.
   - Encode these observations back into `Notes.md` and update this report if clear patterns emerge.

3. **Minimal mach + literal probe**
   - Add a `mach-lookup` + literal-only profile with no subpath (e.g., mach plus `literal "/etc/hosts"` but no extra read rules) to see whether:
     - field2=6 appears without subpath,
     - op-table entries move into the `[6,…,5]` family,
     - tag6 emerges without additional operations.
   - This will help disentangle “mach vs subpath vs multi-branching” in the tag6/field2=6 story.

4. **Per-op graph signatures (optional within this experiment)**
   - Reuse the decoder to implement small graph walks from op-table entrypoints (as in the op-table experiment), but keep the output local to this directory:
     - for each op-table entry, record reachable tags and `field2` values,
     - compare signatures between profiles that differ by a single Operation.
   - This remains ID-agnostic but offers a structural view that can later be tied to an Operation Vocabulary Map.

5. **Integration with vocabulary-mapping work**
   - `book/graph/concepts/validation/out/vocab/ops.json` and `filters.json` now exist (`status: ok` from cache harvest):
     - revisit this experiment to label observed tag/field patterns with concrete Operation/Filter IDs where possible,
     - keep a clear line between labels grounded in vocab artifacts and structural hypotheses when field semantics remain ambiguous (e.g., field2 small integers in filtered profiles).

6. **Turnover discipline**
   - Keep `Plan.md` and `Notes.md` in sync:
     - whenever you add a new SBPL variant, describe why in `Notes.md` and add a brief bullet in `Plan.md`,
     - when a hypothesis is strengthened or disproved, adjust this report and leave the previous version accessible via git history rather than piling on new ad‑hoc sections.

---

## 10. How this experiment feeds the larger project

Within the project’s conceptual model:

- This experiment provides concrete evidence for:
  - the existence and structure of the **Operation Pointer Table** and node region,
  - the role of literal/regex pools in compiled profiles,
  - how **Filters** and **Metafilters** manifest as stable patterns over node tags and small integer fields.
- It supplies reusable artifacts and summaries that:
  - the `op-table-operation` experiment uses to reason about buckets (4/5/6),
  - the `op-table-vocab-alignment` and vocabulary-mapping tasks can leverage once Operation/Filter vocabulary maps exist.

The main value here is not a complete decode of the modern format, but a well-documented, reproducible slice of how today’s Seatbelt PolicyGraphs look on Sonoma, and a clear set of open questions for future agents.***
