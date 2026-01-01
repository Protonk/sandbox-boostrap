# Notes

Record profile variants, probe commands, and observations for graph-shape-vs-semantics runs. Reference derived outputs under `out/derived/<run_id>/`.

- Reused runtime-adversarial structural/mach variants via the unified runtime CLI and emitted a promotion packet for consumption.
- Generated alignment summary via `python book/experiments/graph-shape-vs-semantics/summarize_struct_variants.py --packet <promotion_packet.json>` → `out/derived/<run_id>/graph_shape_semantics_summary.json`. Structural pairs (struct_flat vs struct_nested, for both read and write paths, and mach literal vs regex variants) show identical allow/deny outcomes; path_edges family records the known `/tmp`→`/private/tmp` VFS mismatch for both read and write probes.
