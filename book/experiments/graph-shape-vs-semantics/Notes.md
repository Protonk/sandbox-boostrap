# Notes

Record profile variants, probe commands, and observations for graph-shape-vs-semantics runs. Reference files under `out/`.

- Reused runtime-adversarial structural/mach variants by running `python book/experiments/runtime-adversarial/run_adversarial.py` (now with file-write* rules mirroring file-read* in struct/path_edges families).
- Generated alignment summary via `python book/experiments/graph-shape-vs-semantics/summarize_struct_variants.py` → `out/graph_shape_semantics_summary.json`. Structural pairs (struct_flat vs struct_nested, for both read and write paths, and mach literal vs regex variants) show identical allow/deny outcomes; path_edges family records the known `/tmp`→`/private/tmp` VFS mismatch for both read and write probes.
