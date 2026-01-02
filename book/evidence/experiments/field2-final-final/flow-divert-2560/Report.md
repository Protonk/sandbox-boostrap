# Flow-divert-2560 Experiment

## Purpose
- Resolve the meaning of the `field2` payload `2560` observed on `flow-divert` tags (notably in require-all domain/type/protocol cases) by tying it to concrete anchors or encoder behaviors on the Sonoma baseline.

## Baseline & scope
- Host baseline: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
- Inputs: SBPL probes compiled locally, existing vocab/tag layouts (`book/evidence/graph/mappings/vocab`, `book/evidence/graph/mappings/tag_layouts`), decoder tooling.
- Out of scope: cross-version speculation, non-`flow-divert` field2 payloads except as controls.

## Deliverables / expected outcomes
- Decoded probes showing how `2560` is emitted (filters, tags, anchors).
- Runtime/apply evidence if obtainable (even `blocked` outcomes are recorded).
- Updated local artifacts in `out/` summarizing field2 payload mappings for `flow-divert`.
- Guardrail proposals if `2560` can be pinned to a stable anchor/parameter.

## Plan & execution log
- **Done**: Built compile matrix in `sb/` (singles, pairs, triples; ordering permutations; `require-all`/`require-any`; nested triple; TCP/UDP variants; negative controls on `mach-lookup`).
  - Compiled via `python -m book.api.profile compile book/evidence/experiments/field2-final-final/flow-divert-2560/sb/*.sb --out-dir book/evidence/experiments/field2-final-final/flow-divert-2560/sb/build`.
- **Done**: Decoded with `harvest_matrix.py`, emitting joinable records (`out/matrix_records.jsonl`) and per-spec summaries (`out/field2_summary.json`).
- **Observations**: The matrix yields a stable “flow-divert triple” cluster: `2560` (`0x0a00`) and `1281` (`0x0501`) appear only in the triple specs (both TCP/UDP, any ordering, `require-all`/`require-any`, nested) as tag `0` nodes with `u16_role: filter_vocab_id` and literal `com.apple.flow-divert`. `2816` (`0x0b00`) is also triple-only in this matrix but surfaces in mixed tag/role contexts (sometimes as `arg_u16`), so treat it as a triple-only token without overfitting on a single node shape. Singles and pairs stay on low vocab IDs; negative controls remain low and never produce the triple-only tokens. `anchor_filter_map.json` already lists `flow-divert` (candidates `local`/`xattr`, field2 `[2, 7, 2560]`, status `blocked`), and field2-atlas static records for field2=7 carry the same seed anchor/status. The matrix evidence is consistent and strengthens the `local` interpretation, but no mapping changes made yet.
- **Done**: Baseline against `field2-filters`/`unknown_focus` and `probe-op-structure` outputs; no residual contexts beyond the triple cases.
- **Done**: Cross-checked against `anchor_filter_map`, field2 atlas, and tag-layout contracts; retired 2560 (and, by the same witness, 2816) from the unknown-high set as characterized triple-only tokens and added guardrail coverage in `book/tests/planes/graph/test_field2_unknowns.py`.
- **Pending**: Optional encoder/runtime traces only if needed to distinguish alternative interpretations; record apply gates/EPERMs explicitly.
- **Pending**: If encoder/runtime evidence surfaces, consider mapping 2560 to an explicit encoder-side symbol; otherwise treat as characterized opaque/static.

## Evidence & artifacts
- `sb/` – SBPL sources for probes (matrix covering flow-divert triples and controls).
- `sb/build/` – compiled blobs for the matrix.
- `out/` – decoded artifacts and summaries (`matrix_records.jsonl`, `field2_summary.json`).

## Blockers / risks
- Apply gates may block runtime probes; encoder visibility may be limited.
- `2560` may represent an aggregate or multi-anchor condition, making isolation harder.

## Next steps
- Execute the planned probes and decodes; fill `out/` with inventories.
- Document outcomes and update status once evidence exists.
