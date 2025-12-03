# Operation Pointer Table mappings

Stable Operation Pointer Table artifacts for this host/build.

These files capture how compiled profiles arrange the **Operation Pointer Table**: how many entries exist, which indices are reused (“buckets”), and what structural patterns (node tags, literals, filters) hang off each entry. Together with the vocab maps, they explain how SBPL Operations relate to op-table indices at the PolicyGraph level.

Contents:
- `op_table_vocab_alignment.json` – Op-table entries annotated with operation/filter IDs (via vocab) for synthetic profiles. This is the bridge between op-table buckets and SBPL operation names.
- `op_table_operation_summary.json` – Decoder-backed summaries from `op-table-operation` (per-profile op-count, buckets, and operation sets).
- `op_table_signatures.json` – Structural signatures per op-table entry (tag counts, field2 distributions, reachable nodes). These are fingerprints for how a bucket “looks” in the graph.
- `op_table_map.json` – Bucket map hints from `op-table-operation` describing how buckets change as operations/filters are added.
- `metadata.json` – Host/build and vocab stamps (23E224, ops=196/filters=93, status ok) plus canonical filenames for this mapping set.

Source: `book/experiments/op-table-operation/` and `op-table-vocab-alignment/` on this Sonoma host. Treat these as read-only snapshots when reasoning about which Operation entries a profile actually uses.
