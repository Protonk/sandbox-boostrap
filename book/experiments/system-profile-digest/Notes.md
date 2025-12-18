# System Profile Digest – Notes

Use this file for concise notes on progress, commands, and intermediate findings.

## Initial scaffold

- Experiment scaffolded (plan/report/notes). Goal: decode curated system profiles and publish digests to `book/graph/mappings/system_profiles/digests.json`. No decoding performed yet.

## Baseline decode and digest publish

- Generated digests for canonical system profiles (`airlock`, `bsd`, `sample`) with `book.api.profile_tools.digests` (decoder-backed); wrote interim digest to `out/digests.json` (op-table, node/tag counts, literals, sections, validation) sourced from `book/graph/concepts/validation/fixtures/blobs/{airlock,bsd,sample}.sb.bin`.
- Published normalized digest to `book/graph/mappings/system_profiles/digests.json` (includes host metadata, op-table, tag counts, literal sample, sections, validation) as the reusable artifact.
- Guardrail added via `tests/test_mappings_guardrail.py` to assert digest presence and host metadata.
- Regenerated static checks + digests after tag-layout update (meta tags 2/3, payload tag10); contracts now carry tag_layout_hash `4dd3a3…fc219` and canonical statuses back to `ok`.

## Refresh under stride=8 decode framing

- Added `run.py` and regenerated `out/digests.json` using the current world-scoped decoder framing (8-byte node records selected via op-table witness). Canonical node/section sizes now match the stride=8 slice (`airlock` nodes 1412 bytes / node_count 176; `bsd` nodes 554 bytes; `sample` nodes 440 bytes).
