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
- Pending: `out/encoder_sites.json`.

## Blockers / risks

- Phase B is expected to be partial/brittle unless encoder patterns are obvious; no promotion to `book/graph/mappings/*` without corroboration.

## Next steps

- Stand up Phase A probes and capture the matrix.
- Begin Phase B disassembly once Phase A is stable.
- ### Phase A v1 Status (frozen)

- Tag roles: tag2/tag3 are classified as meta/header (no payload) and are excluded from the encoder matrix. Payload-bearing tags in scope are currently {10,8,6,9}.
- Tag10 layout: field[2] is confirmed as the filter ID slot (values {6,8,9,10} matching the Filter Vocabulary Map). The payload slot for tag10 remains ambiguous between field[3] and field[4] based on matrix_v1; Phase A does not resolve this.
- Matrices: `matrix_v1_field2_encoder_matrix.json` provides a clean, vocab-aligned baseline; `matrix_v2` exists but its decode is skewed (tag6/5 only) and is not used for conclusions.
- Next step: Phase B will inspect libsandbox’s profile serializer to identify the per-tag10 store pattern, resolve the payload offset, and feed that back into tag_layout_overrides and future Phase A matrices.
