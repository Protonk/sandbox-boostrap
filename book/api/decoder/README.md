# Decoder (`book.api.decoder`)

Purpose: decode compiled sandbox profile blobs (`*.sb.bin`) into a structured, version-tolerant summary without enforcing a specific format variant. Outputs are meant to be consumed by experiments (`node-layout`, `op-table-operation`, `field2-filters`, etc.) and mappings under `book/graph/mappings/`.

What it does (current behavior):
- Reads a blob and emits a `DecodedProfile` object (or JSON if you serialize it) with:
  - `preamble_words`: first 16 bytes as little-endian 16-bit words; `op_count` guessed from word 1 when plausible.
  - `op_table_offset` and `op_table`: raw operation-pointer entries (2-byte each) starting at byte 16 for `op_count * 2` bytes.
  - `nodes`: tag-aware slice of the node region using heuristic record sizes (default 12-byte records; tag-specific layouts merged from `book/graph/mappings/tag_layouts/tag_layouts.json` and `probe-op-structure` outputs).
  - `tag_counts`: histogram of node tags; `node_count` and any parsing remainder.
  - `literal_pool` and `literal_strings`: printable runs from the trailing literal/regex region, with offsets preserved internally.
  - `sections`: byte offsets for the op-table, node region, and literal region; `validation` includes basic edge sanity (in-bounds edge counts).
- Keeps decoding conservative: unknown tags fall back to 12-byte stride; failures leave buffers intact rather than guessing.

How to use:
- Import as a module:
  ```python
  from book.api import decoder
  data = Path("sample.sb.bin").read_bytes()
  profile = decoder.decode_profile(data)
  print(profile.op_count, profile.tag_counts, profile.literal_strings[:5])
  ```
- Tag layouts: extend `book/graph/mappings/tag_layouts/tag_layouts.json` (keys: `tag`, `record_size_bytes`, `edge_fields`, `payload_fields`) to refine parsing; the decoder merges those hints automatically.

Notes:
- This decoder is heuristic by design to tolerate format drift across macOS versions; treat outputs as structural orientation, not ground truth SBPL.
- If you change the decoder or tag layouts, rerun dependent experiments and mappings to refresh their `out/*.json` artifacts.
