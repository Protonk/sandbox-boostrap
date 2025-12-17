## Aim

Establish how this host’s `libsandbox` populates the per-node u16 payload slot (historically “field2”, now `field2_raw`/`filter_arg_raw` in decoding) when compiling SBPL, and relate the observed values back to the Filter Vocabulary Map (`book/graph/mappings/vocab/filters.json`, status: ok) *only when the tag’s u16 role warrants it*. The kernel is treated as a black box that consumes a compiled blob; this experiment focuses on userland emission and structural alignment.

## Phases

- **Phase A — SBPL→blob matrix (encoder output view)**
  - Use `book/api/sbpl_compile` + `profile_ingestion` + stride=8 node parsing to produce a stable, reproducible “encoder matrix” over a small SBPL probe set.
  - Record per observed node: tag, raw u16 payload (`field2_raw`), hi/lo split (`field2_hi`/`field2_lo`), and any heuristic literal refs.
  - For tags whose payload role is `filter_vocab_id` (see `book/graph/mappings/tag_layouts/tag_u16_roles.json`), also attempt `filters.json` resolution and record `filter_name`. For tags whose role is `arg_u16`, keep the payload as opaque u16 (do not treat in-range values as proof of a vocab ID).
  - First pass stays regex-free to reduce confounders; follow-up matrices can add regex-bearing probes once the structural picture is stable.

- **Phase B — libsandbox internals (encoder implementation view)**
  - Inspect the trimmed `libsandbox` slice under `book/graph/mappings/dyld-libs/` (static only).
  - Identify emitters for the condition-data payloads (e.g., network domain/type/proto) and tie those byte writes to the compiled blob’s sections.
  - Summarize encoder-side sites and their observed write order/widths in a small JSON (`out/encoder_sites.json`), without claiming kernel semantics.

## Deliverables

- **Phase A**
  - `out/matrix_v1_field2_encoder_matrix.json` and `out/matrix_v2_field2_encoder_matrix.json` (current encoder matrices).
  - SBPL probes under `sb/` plus compiled blobs in `out/`.
- **Phase B**
  - `out/encoder_sites.json` (static RE notes with addresses and write-order evidence).
- Updated `Report.md` with current status, evidence pointers, and remaining gaps.

## Status

- Phase A: implemented and refreshed under the world-scoped stride=8 framing; matrices emitted as `out/matrix_v*_field2_encoder_matrix.json`.
- Phase B: partial; initial encoder-site mapping captured in `out/encoder_sites.json`.
