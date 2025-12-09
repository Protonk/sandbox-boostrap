# Anchor mappings

Stable anchor-derived mappings live here.

Current artifacts:
- `anchor_field2_map.json` – Anchor → `field2` hints derived from `probe-op-structure` anchor hits. Each anchor is a human-meaningful literal (path, mach name, iokit class) that the experiments have tied to one or more `field2` values and node indices.
- `anchor_filter_map.json` – Anchor → Filter-ID/name map (confidence varies by anchor; see `status` fields; includes host metadata). This file interprets the `field2` hints using the Filter Vocabulary Map and expresses anchors directly in terms of Filters.

Role in the substrate:
- Anchors come from SBPL- or profile-level literals (paths, mach names, etc.) and serve as stable “handles” for specific filters in the PolicyGraph.
- Together these maps connect the **literal world** (file paths, mach names) to **Filter** semantics and `field2` encodings, which is essential when reconstructing SBPL-style rules from compiled profiles or building capability catalogs around concrete resources.

## Evidence and guardrails

These mappings are **not** free-floating. They are driven by, and constrained by, the `book/experiments/probe-op-structure` experiment:

- `anchor_field2_map.json` and the `field2_values` in `anchor_filter_map.json` are derived from `book/experiments/probe-op-structure/out/anchor_hits.json`, which is produced by decoding probe and system profiles via `book/api/decoder` under the canonical tag layouts (`book/graph/mappings/tag_layouts/tag_layouts.json`).
- `book/tests/test_anchor_filter_alignment.py` enforces that every mapped, non‑blocked anchor in `anchor_filter_map.json` (an entry with a `filter_id` and `sources`, `status != "blocked"`) is backed by concrete witnesses in `anchor_hits.json`:
  - there must be at least one observation for that anchor under the listed `sources`,
  - the pinned `filter_id` must appear among the observed `field2_values`, and
  - all observed `field2_values` must be listed in the mapping’s `field2_values`.

If this guardrail fails, you must reconcile **either** the experiment outputs **or** the mapping (or both) so that each mapped anchor is supported by the current `anchor_hits.json`. For the structural story, limitations, and next steps of the experiment that feeds these mappings, see `book/experiments/probe-op-structure/Report.md`.
