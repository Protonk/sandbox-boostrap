# profile_tools.decoder

Host-scoped structural decoder for compiled sandbox profile blobs on the Sonoma baseline (`world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`).

This surface is intentionally **structural**:
- Inputs are compiled blobs (`.sb.bin`).
- Outputs are a best-effort parsed view of header fields, op-table entries, node records, and literal/regex pools.
- It does **not** claim kernel semantics; it is a way to make blob structure inspectable and falsifiable.

## Current surface

### Library API (stable)

- `from book.api.profile_tools.decoder import decode_profile, decode_profile_dict`
- `from book.api.profile_tools.decoder import DecodedProfile`
- Heuristic constants used by downstream tooling:
  - `WORD_OFFSET_BYTES` (current scaling used for op-table alignment scoring)
  - `DEFAULT_TAG_LAYOUTS`
  - `ROLE_UNKNOWN`

`decode_profile(data: bytes, *, node_stride_bytes: int | None = None) -> DecodedProfile` returns a dataclass that includes:
- section boundaries and offsets (via `book.api.profile_tools.ingestion`),
- parsed node records (either “tag-layout” mode or fixed-stride mode),
- optional annotations from published mappings (when present),
- a `validation` block containing stride-selection metrics and other structural witnesses.

`decode_profile_dict(...) -> dict` is the JSON-safe wrapper used by CLIs and validation tooling.

### CLI

`python -m book.api.profile_tools decode dump <blobs...> [--summary] [--bytes N] [--node-stride 8|12|16] [--out PATH]`

## Annotations (mapping-assisted, optional)

When the repo mappings exist and the repo root can be resolved, the decoder will try to add light annotations:
- Tag layouts: `book/graph/mappings/tag_layouts/tag_layouts.json` (or fallback `book/experiments/probe-op-structure/out/tag_layout_assumptions.json`)
- Per-tag u16 role hints: `book/graph/mappings/tag_layouts/tag_u16_roles.json`
- Filter vocab join (id → name): `book/graph/mappings/vocab/filters.json`

If these files are missing or unreadable, decoding still proceeds but those annotations are omitted.

## Node framing (heuristic)

The decoder supports two node parsing modes:
- **Tag-layout mode**: uses per-tag `record_size_bytes` when available, defaulting to 12-byte records.
- **Fixed-stride mode**: parses nodes as fixed-size records (for example 8 bytes), selected automatically from op-table alignment evidence or forced via `node_stride_bytes` / `--node-stride`.

The returned `DecodedProfile.validation.node_stride_selection` and `validation.op_table_scaling_witness` blocks are intended as the primary “why did the decoder choose this framing?” witnesses.

## Code layout

- `book/api/profile_tools/decoder/api.py`: decoder implementation and the `DecodedProfile` contract.

