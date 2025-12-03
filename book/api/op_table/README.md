# Op Table

Helpers for op-table centric analysis on the Sonoma baseline.

Features:
- Parse allowed ops/filters from SBPL.
- Summarize compiled blobs: op_entries, tag counts, literal strings, entry signatures.
- Optional vocab alignment using `book/graph/mappings/vocab/ops.json` and `filters.json`.

Surfaces:
- Python: `parse_ops`, `parse_filters`, `summarize_profile`, `entry_signature`, `build_alignment`.
- CLI: `python -m book.api.op_table.cli <blob|sb> [--compile] [--op-count N] [--vocab ops.json --filters filters.json] [--json OUT]`.

Host: see `book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json`.
