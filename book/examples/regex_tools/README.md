# Regex Tools (legacy AppleMatch)

**HISTORICAL EXAMPLE.** This directory is maintained for historical inspection of legacy decision-tree sandbox profiles and their embedded AppleMatch regex tables. It is not a model of the modern graph-based compiled profile format used on this host baseline.

Legacy helpers for decision-tree sandbox profiles that embed AppleMatch regex tables. Modern graph-based profiles use different storage; these scripts are for historical inspection only.

- `extract_legacy.py` – extract compiled AppleMatch blobs (`.re`) from legacy profiles using the header’s `re_table_offset`/`re_table_count`.
- `re_to_dot.py` – render a compiled `.re` blob into a Graphviz `.dot` file for visualization.

Host baseline: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`. Inputs should be legacy-format profiles from this host.
