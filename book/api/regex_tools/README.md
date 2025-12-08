# Regex Tools (legacy AppleMatch)

Helpers for the early decision-tree sandbox profile format. Modern graph/bundled profiles store regex tables differently; these tools intentionally stay scoped to the legacy layout.

- `extract_legacy.py` – extract compiled AppleMatch blobs (`.re`) from legacy profiles using the header’s `re_table_offset`/`re_table_count`.
- `re_to_dot.py` – render a compiled `.re` blob into a Graphviz `.dot` file for visualization.

Host assumptions: see `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5 (baseline: book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json)`; inputs should come from decoded legacy profiles under this baseline.
