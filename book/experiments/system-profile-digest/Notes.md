# System Profile Digest – Notes

Use this file for dated, concise notes on progress, commands, and intermediate findings.

## 2025-12-10

- Experiment scaffolded (plan/report/notes). Goal: decode curated system profiles and publish digests to `book/graph/mappings/system_profiles/digests.json`. No decoding performed yet.

## 2025-12-11

- Decoded canonical system profiles (`airlock`, `bsd`, `sample`) with `book.api.decoder`; wrote interim digest to `out/digests.json` (op-table, node/tag counts, literals, sections, validation) sourced from `book/examples/extract_sbs/build/profiles/{airlock,bsd}.sb.bin` and `book/examples/sb/build/sample.sb.bin`.
- Published normalized digest to `book/graph/mappings/system_profiles/digests.json` (includes host metadata, op-table, tag counts, literal sample, sections, validation) as the reusable artifact.
- Guardrail added via `tests/test_mappings_guardrail.py` to assert digest presence and host metadata.
