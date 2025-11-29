# Tag Layout Decode – Research Report (Sonoma / macOS 14.4.1)

## Purpose

Map node tags that reference literal or regex pools to interpretable layouts (edge fields plus operand fields) using the current decoder and anchor hits. Produce a reusable map at `book/graph/mappings/tag_layouts/tag_layouts.json` for other tooling and book chapters.

## Baseline and scope

- Host: macOS 14.4.1 (23E224), Apple Silicon, SIP enabled (same baseline as other experiments).
- Inputs: canonical system profiles (`book/examples/extract_sbs/build/profiles/{airlock,bsd,sample}.sb.bin`), probe outputs from `probe-op-structure`, and shared vocab/op-table mappings in `book/graph/mappings/`.
- Tooling: `book.api.decoder` for profile decoding; anchor hints from `book/graph/mappings/anchors/anchor_field2_map.json`.
- Target artifact: `book/graph/mappings/tag_layouts/tag_layouts.json` (per-tag layout with operand interpretation and provenance).

## Plan (summary)

1. Baseline decode and histogram of reference blobs to identify tags that carry literal/regex operands.
2. Reconstruct per-tag field meanings (edges vs operands) using literal/regex tables and anchor hits.
3. Synthesize a stable tag-layout map and add guardrail checks against reference blobs.

## Current status

- Experiment scaffolded (this report, Plan, Notes).
- Baseline decode complete for canonical system profiles (`airlock`, `bsd`, `sample`); tag counts and literal counts recorded in `out/tag_histogram.json`. Decoder inputs: `book/examples/extract_sbs/build/profiles/{airlock,bsd}.sb.bin`, `book/examples/sb/build/sample.sb.bin`.
- Sample literal-bearing nodes grouped by tag captured in `out/tag_literal_nodes.json` to support layout interpretation.
- Best-effort tag layouts published at `book/graph/mappings/tag_layouts/tag_layouts.json` (record_size=12, edges fields[0..1], payload field[2] for literal-bearing tags 0,1,3,5,7,8,17,26,27,166). Decoder now prefers this mapping when present. Guardrail test added (`tests/test_mappings_guardrail.py`) to ensure the mapping persists.

## Expected outcomes

- A per-tag layout map for literal/regex-bearing nodes with evidence trails.
- Guardrail script/test that asserts expected literal/regex placements on reference blobs.
- Updated Notes and Plan with any deviations or open questions.
