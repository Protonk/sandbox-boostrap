# Outputs

Produced by the scripts in `book/evidence/experiments/field2-final-final/probe-op-structure/`. Anchors probe SBPL variants plus a few system profiles to inspect node field usage, literals, and `field2` values.

- `analysis.json` — per-profile op counts, node counts, field2 histograms (with filter-name mapping), literal samples.
- `tag_layout_*` / `tag_inventory.json` / `tag_bytes.json` — tag-level observations that informed early decoder tag-layout hypotheses (now superseded for covered tags by `book/integration/carton/bundle/relationships/mappings/tag_layouts/tag_layouts.json`).
- `literal_scan.json` — supporting slices for tag/layout and literal-offset reasoning.
- `anchor_hits.json` — per-profile, per-anchor node indices and `field2` values; this is the primary witness used by `book/integration/tests/graph/test_anchor_filter_alignment.py` to keep `book/integration/carton/bundle/relationships/mappings/anchors/anchor_filter_map.json` aligned with experiment outputs.
- `tranche_witness.json` — tranche-scoped structural witness for `book/evidence/experiments/field2-final-final/out/tranche.json` (the selected `field2` value, inventory hits, and exact decoded nodes carrying that payload).

These files are treated as fixtures for decoder and mapping explorations; tests look for their presence and broad shape, not exact values. Regenerate via:

- `python3 book/evidence/experiments/field2-final-final/probe-op-structure/analyze_profiles.py`
- `python3 book/evidence/experiments/field2-final-final/probe-op-structure/anchor_scan.py`
- `python3 book/evidence/experiments/field2-final-final/probe-op-structure/tranche_witness.py`

after adjusting probe SBPL or vocab.
