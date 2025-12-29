# profile.ingestion

Host-scoped profile ingestion helpers for the Sonoma baseline (`world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`).

This surface is intentionally **structural**:
- Inputs are compiled profile blob bytes (`.sb.bin`).
- Outputs are header classification plus byte slices for major sections (`op_table`, `nodes`, `regex_literals`) with explicit byte offsets.
- It does **not** interpret sandbox semantics; downstream tooling (decoder/inspect/op-table) builds on these slices.

## Current surface

### Library API (stable)

- `from book.api.profile.ingestion import ProfileBlob, Header, Sections, SectionOffsets`
- `from book.api.profile.ingestion import parse_header, slice_sections, slice_sections_with_offsets`

Contract:
- `parse_header(ProfileBlob) -> Header` classifies the blob as either:
  - `legacy-decision-tree` (older decision-tree layout), or
  - `modern-heuristic` (graph-based blobs on this baseline; heuristic).
- `slice_sections_with_offsets(ProfileBlob, Header) -> (Sections, SectionOffsets)` returns:
  - `Sections(op_table: bytes, nodes: bytes, regex_literals: bytes)`
  - `SectionOffsets(op_table_start/end, nodes_start/end, literal_start/end)` (absolute byte offsets into the input blob)

`slice_sections(ProfileBlob, Header) -> Sections` is the convenience wrapper when offsets are not needed.

## Offsets and provenance (why `SectionOffsets` exists)

Many repo artifacts (validation IR, experiment outputs, guardrail fixtures) need to record *where* a value came from in the blob, not just the value.

Callers should prefer `slice_sections_with_offsets` and carry offsets forward as the primary witness:
- offsets keep downstream decoders honest about where boundaries were inferred,
- offsets let tools report stable “byte-level” witnesses without re-slicing,
- offsets make it easier to diff/triage format drift across blobs on the same baseline.

When emitting JSON that includes blob paths, use repo-relative paths via `book.api.path_utils.to_repo_relative`.

## Format heuristics (baseline-scoped)

This module implements format classification and section slicing using host-scoped heuristics:
- **Legacy decision-tree**: uses a u16 regex-table offset (in 8-byte words) and an op-table region between the fixed header and regex/literal data.
- **Modern (graph-based) heuristic**:
  - treats bytes `[0x10 .. 0x10 + op_count*2)` as the op-table (where `op_count` is a small u16 header word when present),
  - treats the node stream as beginning immediately after the op-table,
  - finds a conservative lower bound for the literal pool start from the max op-table target scaled by 8-byte words (to avoid truncating node bytes due to “ASCII-looking” runs inside nodes),
  - then uses a conservative printable-run scan (with a minimal Mach-O segment parser fallback) to find the literal/regex pool start.

These are structural guesses for this world baseline, not cross-version guarantees.

## Relationship to validation

`book/api/profile/ingestion/api.py` intentionally mirrors the ingestion helpers in `book/graph/concepts/validation/profile_ingestion.py` so that non-validation callers can import a stable API surface without reaching into the validation layer.

If you change the ingestion contract or slicing heuristics, keep the two copies aligned and run `make -C book test`.

## Code layout

- `book/api/profile/ingestion/api.py`: implementation and dataclasses (`ProfileBlob`, `Header`, `Sections`, `SectionOffsets`).
