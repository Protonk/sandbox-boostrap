# Outputs

Produced by `book/experiments/probe-op-structure/analyze_profiles.py` and related helpers. Anchors probe SBPL variants plus a few system profiles to inspect node field usage and literals.

- `analysis.json` — per-profile op counts, node counts, field2 histograms (with filter-name mapping), literal samples.
- `tag_layout_*` / `tag_inventory.json` / `tag_bytes.json` — tag-level observations that inform decoder tag layouts.
- `anchor_hits.json`, `literal_scan.json`, `summary.json` — supporting slices for tag/layout reasoning.

These files are treated as fixtures for decoder and mapping explorations; tests look for their presence and broad shape, not exact values. Regenerate via `analyze_profiles.py` after adjusting probe SBPL or vocab.***
