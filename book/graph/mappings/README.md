Stable graph-level mapping artifacts live here (versioned by host/build when applicable).

These files are the “shared IR” that tie together experiments, the decoder, and the textbook. They describe how **Operations**, **Filters**, **PolicyGraph** nodes, and concrete system profiles line up on this host, so other tools do not need to rediscover the same facts.

Metadata conventions:
- Top-level shape is `{"metadata": {...}, <payload_key>: ...}`. Payload keys name the data (`ops`, `filters`, `profiles`, `records`, `tags`, `entries`, etc.) and avoid mixing metadata with data rows.
- `host` fields reference the world baseline by path (`world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5 (baseline: book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json)`) instead of inlining host traits.
- Timestamps are intentionally omitted; provenance lives in `inputs` / `source_jobs` and content hashes.

Subdirectories:
- `vocab/` – Operation / Filter Vocabulary Maps harvested from `libsandbox` for this host. This is the canonical **Operation Vocabulary Map** and **Filter Vocabulary Map** the rest of the project uses when decoding profiles or building capability catalogs.
- `op_table/` – Compiled-profile **Operation Pointer Table** view: bucket maps, structural signatures, and vocab alignment from the op-table experiments. These artifacts explain how op-table indices relate to SBPL operations at the structural level.
- `anchors/` – Anchor-derived mappings from `probe-op-structure` tying human-meaningful strings (paths, mach names, iokit classes) to `field2` values and Filters. This folder connects literal anchors in SBPL to Filter semantics in the PolicyGraph.
- `tag_layouts/` – Tag-level PolicyGraph layouts describing how node tags map to record sizes, edge fields, and payload fields (literal/regex operands). This is the binary counterpart to “filter/metafilter node” structure in Concepts.
- `system_profiles/` – Canonical decoded digests for selected system profiles on this host (e.g., `airlock`, `bsd`, `sample`) plus attestations tying blob hashes, op-table entries, tag counts, literal/anchor hits, and vocab/tag-layout/runtime links together. These ground the abstract concepts in real PolicyGraphs and keep them reproducible.
- `runtime/` – Runtime probe expectations and (when possible) traces from running profiles under Seatbelt. This connects decoder-level predictions to observed allow/deny decisions in the live sandbox.
- `vocab/` – Operation/Filter vocabulary maps with attestations linking the tables to dyld slices and reference blobs for this host/build.
- `carton/` – CARTON-derived overlays (e.g., operation coverage) built purely from the frozen CARTON interface, not raw experiment outputs.
