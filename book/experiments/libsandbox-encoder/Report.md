## Purpose

Map how this host’s `libsandbox` encodes filter arguments into the `field2` u16 in compiled profiles and align those encodings with the Filter Vocabulary Map (`book/graph/mappings/vocab/filters.json`, status: ok). The kernel is treated as consuming a raw u16; the focus here is purely on userland emission.

## Baseline & scope

- Host: macOS 14.4.1 (23E224), Apple Silicon, SIP enabled (`book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json`).
- Inputs: `book/api/sbpl_compile`, `book/api/decoder`, trimmed `libsandbox` slice under `book/graph/mappings/dyld-libs/`.
- Out of scope: runtime `sandbox_apply` or kernel-side interpretation (covered by `field2-filters`).

## Plan & execution log

- Phase A — SBPL→blob matrix (encoder output view): matrix v1 (regex-free) compiled via `sbpl_compile`; nodes parsed via `profile_ingestion` + custom helper with local tag overrides; table emitted to `out/matrix_v1_field2_encoder_matrix.json`. Tag2/tag3 treated as meta/no payload; tag10 field[2] = filter ID, payload slot remains ambiguous (field[3]/[4]).
- Phase B — libsandbox internals (encoder implementation view): not started (next step; proceed to serializer/encoder site identification).

## Evidence & artifacts

- `sb/matrix_v1.sb` (regex-free baseline); `sb/matrix_v2.sb` (arg-variance probe; decode pending infra fixes).
- `out/tag_layout_overrides.json` (local, staged) for tags 2/3/8/10.
- `out/matrix_v1.sb.bin`, `out/matrix_v1.inspect.json`, `out/matrix_v1.op_table.json`, `out/matrix_v1_field2_encoder_matrix.json` (Phase A table with tag2/3 excluded).
- `out/matrix_v2.sb.bin`, `out/matrix_v2.inspect.json`, `out/matrix_v2_field2_encoder_matrix.json` (decode currently skewed to tag6/5; not relied on).
- `dump_raw_nodes.py` (heuristic node dumper used in Phase B). For `matrix_v1.sb.bin` it locates a 12-byte-stride node block at [0,480) and shows the seven records closest to the literal pool as:
  - 396: [0, 0, 2560, 21, 10, 1]
  - 408: [3328, 6, 9, 2, 3072, 1]
  - 420: [9, 3, 2816, 2, 9, 10]
  - 432: [1536, 11, 9, 5, 1792, 16]
  - 444: [9, 10, 4352, 5, 9, 7]
  - 456: [4608, 8, 9, 10, 256, 0]
  - 468: [9, 10, 1281, 0, 0, 0]
- Pending: `out/encoder_sites.json`.

## Blockers / risks

- Phase B is expected to be partial/brittle unless encoder patterns are obvious; no promotion to `book/graph/mappings/*` without corroboration.

## Phase B notes (in-progress)

- Serializer context (manual RE): in the “bytecode_output.c” region (`0x183d01f*`), the compiler sets `x22 = builder + 0xe98` and uses that pointer for `_sb_mutable_buffer_set_minimum_size` and `_sb_mutable_buffer_write`. The same base+0xe98 is passed through `_emit`, `_emit_instruction`, `_emit_pattern`, etc., so offset 0xe98 is the mutable buffer handle for the compiled profile. `_encode_address` also touches `[ctx, #0xe98]` (on overflow it stores an error there), reinforcing that 0xe98 is the buffer field in the builder.
- Finalize/hand-off to `__sandbox_ms` still to be confirmed: need to follow the builder’s finalize path (post `_sb_mutable_buffer_make_immutable`) up to the caller that packages `buf,len` for `__sandbox_ms` to cement “this is the blob we decode”.
- Next mapping task: in `_emit_network`/`_record_condition_data`, watch the write cursor around the three `_emit` calls (domain/type/proto), derive their byte offsets, and align those emitted bytes to the tag10 halfwords we dumped (offsets 396–468) to fix the payload field.

## Next steps

- Stand up Phase A probes and capture the matrix.
- Begin Phase B disassembly once Phase A is stable.
- ### Phase A v1 Status (frozen)

- Tag roles: tag2/tag3 are classified as meta/header (no payload) and are excluded from the encoder matrix. Payload-bearing tags in scope are currently {10,8,6,9}.
- Tag10 layout: field[2] is confirmed as the filter ID slot (values {6,8,9,10} matching the Filter Vocabulary Map). The payload slot for tag10 remains ambiguous between field[3] and field[4] based on matrix_v1; Phase A does not resolve this.
- Matrices: `matrix_v1_field2_encoder_matrix.json` provides a clean, vocab-aligned baseline; `matrix_v2` exists but its decode is skewed (tag6/5 only) and is not used for conclusions.
- Next step: Phase B will inspect libsandbox’s profile serializer to identify the per-tag10 store pattern, resolve the payload offset, and feed that back into tag_layout_overrides and future Phase A matrices.
