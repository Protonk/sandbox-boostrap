# System Profile Digest – Notes

Use this file for concise notes on progress, commands, and intermediate findings.

Archived: experiment-local `out/` artifacts and helper scripts were removed; the canonical output is `book/graph/mappings/system_profiles/digests.json`. See `Examples.md` for small excerpts.

## Initial scaffold

- Experiment scaffolded (plan/report/notes). Goal: decode curated system profiles and publish digests to `book/graph/mappings/system_profiles/digests.json`. No decoding performed yet.

## Baseline decode and digest publish

- Generated digests for canonical system profiles (`airlock`, `bsd`, `sample`) with `book.api.profile_tools.digests` (decoder-backed), sourced from `book/graph/concepts/validation/fixtures/blobs/{airlock,bsd,sample}.sb.bin`.
- Published normalized digest to `book/graph/mappings/system_profiles/digests.json` (includes host metadata, op-table, tag counts, literal sample, sections, validation) as the reusable artifact.
- Guardrail added via `tests/test_mappings_guardrail.py` to assert digest presence and host metadata.
- Regenerated static checks + digests after tag-layout update; contracts and canonical statuses returned to `ok`.

## Refresh under stride=8 decode framing

- Refreshed under the world-scoped decoder framing (8-byte node records selected via op-table witness). Canonical node/section sizes now match the stride=8 slice (`sys:airlock` nodes 1412 bytes / node_count 176; `sys:bsd` nodes 554 bytes; `sys:sample` nodes 440 bytes).
