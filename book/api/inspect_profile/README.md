# Inspect Profile

Read-only inspection helpers for compiled sandbox profiles on the Sonoma baseline.

Use cases:
- Quick snapshot of blob structure: format variant, op_count, section sizes.
- Stride/tag stats for node regions across common strides (8/12/16).
- Literal string extraction and decoder echo for cross-checking parsers.

Surfaces:
- Python: `summarize_blob(bytes, strides=(8,12,16)) -> Summary`.
- CLI: `python -m book.api.inspect_profile.cli <blob|sb> [--compile] [--json OUT]`.

Dependencies: `book.api.decoder`, `book.graph.concepts.validation.profile_ingestion`, optional `book.api.sbpl_compile` when compiling SBPL first.

Host: see `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5 (baseline: book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json)`.
