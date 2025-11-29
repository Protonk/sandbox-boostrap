# Op-table vs Operation Mapping Experiment (Sonoma host)

Goal: empirically tie operation names (SBPL ops) to op-table entry indices and observed graph entrypoints in compiled profiles, so we can ground the “Operation vocabulary map” and per-operation graph segmentation claims. Keep everything reproducible and versioned using only local tooling and probes.

---

## 1. Setup and scope

**Done**

- Defined the core operation set to probe (file-read*, file-write*, mach-lookup, network-outbound, and a baseline profile).
- Created single-op and paired-op SBPL profiles under `sb/` covering these operations.
- Added `analyze.py` to compile all variants and emit op_count, op_entries, stride-12 tag counts, remainders, and literal summaries.

**Upcoming**

- Only extend the operation set if new structural questions arise.

Deliverables:
- `sb/*.sb` variants + compiled blobs under `sb/build/`.
- `out/summary.json` (per-variant structured data).
- A correlation artifact `out/op_table_map.json` that attempts to map op names → op-table index guess.

---

## 2. Data collection and correlation

**Done**

- Compiled all `sb/*.sb` variants and produced `out/summary.json`.
- Built `out/op_table_map.json` capturing op_entries, unique buckets, and operation sets per profile, including filter annotations.

**Upcoming**

- Re-run the analyzer only when vocab or decoder behavior changes.

---

## 3. Cross-check with semantic probes (optional stretch)

**Done**

- Reused the shared decoder to walk from each op-table entrypoint and record per-entry signatures (tag_counts, field2 distributions, reachable literals), stored in `out/op_table_signatures.json`.

**Upcoming (stretch)**

- Optionally run existing semantic probes via `book/api/SBPL-wrapper/wrapper` (SBPL or blob) and annotate runtime traces with op-table slots and structural signatures, writing any such results to `out/runtime_usage.json`.

---

## 4. Documentation and reporting

**Done**

- Kept dated notes in `Notes.md`.
- Summarized findings and open questions in `ResearchReport.md`.
- Ensured outputs are scoped to the Sonoma host/build.

---

## 5. Open questions to resolve

These remain the main open conceptual questions for future work:

**Upcoming**

- Use decoder-backed signatures and vocab alignment to pin specific op names to the distinct op-table entries in non-uniform patterns (e.g., `[6,…,5]` profiles).
- Study how non-uniform entries move when adding/removing particular operations, and whether node/tag deltas can provide secondary evidence for op→entry mapping.
- Explore the interaction between filters/literals and op-table buckets (e.g., why filtered `file-read*` shifts buckets and how mach/literal/subpath combinations produce `[6,…,5]`).
