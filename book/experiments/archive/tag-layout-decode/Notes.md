# Tag Layout Decode – Notes

Use this file for concise notes on progress, commands, and intermediate findings.

Archived: scratch `out/` artifacts and experiment-local helper scripts were removed; the canonical output is `book/graph/mappings/tag_layouts/tag_layouts.json`. See `Examples.md` for small excerpts.

## Initial scaffold

- Experiment scaffolded (plan/report/notes). Goal is to decode literal/regex-bearing tag layouts and publish `book/graph/mappings/tag_layouts/tag_layouts.json`. No decoding runs yet.

## Baseline decode and first layouts

- Baseline decode of canonical system profiles (`airlock`, `bsd`, `sample`) via `book.api.profile_tools.decoder` to understand tag usage and literal-bearing node shapes. Source blobs: `book/graph/concepts/validation/fixtures/blobs/{airlock,bsd,sample}.sb.bin`.
- Published canonical tag layouts to `book/graph/mappings/tag_layouts/tag_layouts.json` (`metadata.status: ok`, `record_size_bytes: 8`, `edge_fields: [0,1]`, `payload_fields: [2]`) and added guardrail coverage in `book/tests/test_mappings_guardrail.py`.

## Updated

- Updated: reconciled earlier pre-witness framing assumptions; the canonical mapping and decoder stride selection are now world-scoped and guardrailed.
