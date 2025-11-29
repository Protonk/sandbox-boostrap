# Tag Layout Decode – Notes

Use this file for dated, concise notes on progress, commands, and intermediate findings.

## 2025-12-10

- Experiment scaffolded (plan/report/notes). Goal is to decode literal/regex-bearing tag layouts and publish `book/graph/mappings/tag_layouts/tag_layouts.json`. No decoding runs yet.

## 2025-12-11

- Baseline decode of canonical system profiles (`airlock`, `bsd`, `sample`) via `book.api.decoder`; wrote `out/tag_histogram.json` capturing tag counts and literal counts plus sections. Source blobs: `book/examples/extract_sbs/build/profiles/{airlock,bsd}.sb.bin`, `book/examples/sb/build/sample.sb.bin`.
- Extracted literal-bearing nodes grouped by tag from the same blobs; wrote `out/tag_literal_nodes.json` with sample fields/hex/literals for up to three nodes per tag to inform layout reconstruction.
- Published best-effort tag layouts (record_size=12, edges fields[0..1], payload field[2] for literal-bearing tags 0,1,3,5,7,8,17,26,27,166) to `book/graph/mappings/tag_layouts/tag_layouts.json`; decoder now loads layouts from that mapping. Added guardrail `tests/test_mappings_guardrail.py` to assert presence/shape.
