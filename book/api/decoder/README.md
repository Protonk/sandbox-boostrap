# Decoder (`book.api.decoder`)

Role: decode compiled sandbox blobs (`*.sb.bin`) into a structured, tag-aware snapshot without assuming a specific format variant.

Use when: you need a programmatic view of a profile’s PolicyGraph (op-table, nodes, literal pool) for experiments such as `node-layout`, `op-table-operation`, `field2-filters`, or for refreshing mappings under `book/graph/mappings/`.

Host baseline: see `book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json`; Operation/Filter vocabularies come from `book/graph/mappings/vocab/{ops,filters}.json`.

Status: **heuristic**. Unknown tags fall back to a 12-byte stride; the decoder keeps buffers intact rather than guessing. Treat outputs as structural orientation, not ground-truth SBPL semantics.

Surfaces:
- Python: `decode_profile(blob: bytes) -> DecodedProfile` with fields such as:
  - `preamble_words`, `preamble_words_full`, `header_bytes`
  - `op_table_offset`, raw `op_table`
  - `nodes`, `tag_counts`, `node_count`
  - `literal_pool`, `literal_strings`
  - `sections`, `header_fields`, `validation`
- CLI: `python -m book.api.decoder dump <blob...> [--bytes 128] [--summary] [--out path]` for JSON snapshots (header bytes, preamble, sections, tag histogram).

Tag layouts: merged automatically from `book/graph/mappings/tag_layouts/tag_layouts.json` and probe outputs. Extend that mapping (`record_size_bytes`, `edge_fields`, `payload_fields`) to refine parsing; rerun dependent experiments after changes.
