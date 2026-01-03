Stable graph-level mapping artifacts live under `book/integration/carton/bundle/relationships/mappings/` (versioned by host/build when applicable). This directory hosts the generators and documentation for those artifacts.

These files are the “shared IR” that tie together experiments, the decoder, and the textbook. They describe how **Operations**, **Filters**, **PolicyGraph** nodes, and concrete system profiles line up on this host, so other tools do not need to rediscover the same facts.

Metadata conventions:
- Top-level shape is `{"metadata": {...}, <payload_key>: ...}`. Payload keys name the data (`ops`, `filters`, `profiles`, `records`, `tags`, `entries`, etc.) and avoid mixing metadata with data rows.
- `host` fields reference the world baseline by path (`world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`) instead of inlining host traits.
- Timestamps are intentionally omitted; provenance lives in `inputs` / `source_jobs` and content hashes.

Subdirectories (generators):
- `vocab/` – Operation / Filter Vocabulary Map generator; outputs under `book/integration/carton/bundle/relationships/mappings/vocab/`.
- `op_table/` – Operation Pointer Table generator; outputs under `book/integration/carton/bundle/relationships/mappings/op_table/`.
- `anchors/` – Anchor-derived mapping generators; outputs under `book/integration/carton/bundle/relationships/mappings/anchors/`.
- `tag_layouts/` – Tag layout generator; outputs under `book/integration/carton/bundle/relationships/mappings/tag_layouts/`.
- `system_profiles/` – System profile digest/attestation generators; outputs under `book/integration/carton/bundle/relationships/mappings/system_profiles/`.
- `runtime/` – Runtime mapping generators; outputs under `book/integration/carton/bundle/relationships/mappings/runtime/` and `book/integration/carton/bundle/relationships/mappings/runtime_cuts/`.
- CARTON overlays live under `book/integration/carton/bundle/relationships/` (relationships) and `book/integration/carton/bundle/views/` (indices), with contracts + manifest under `book/integration/carton/bundle/`. The anchor → field2 relationship is published via `book/integration/carton/bundle/relationships/anchor_field2.json`, derived from `book/integration/carton/bundle/relationships/mappings/anchors/anchor_field2_map.json` and `book/evidence/experiments/field2-final-final/probe-op-structure/out/anchor_hits.json`.
