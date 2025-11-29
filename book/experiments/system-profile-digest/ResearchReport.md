# System Profile Digest – Research Report (Sonoma / macOS 14.4.1)

## Purpose

Produce stable digests for curated system profile blobs (e.g., `airlock`, `bsd`, `sample`) using the current decoder. These digests should capture op-table buckets, tag counts, literals, and basic section info, and live at `book/graph/mappings/system_profiles/digests.json` for reuse across the book.

## Baseline and scope

- Host: macOS 14.4.1 (23E224), Apple Silicon, SIP enabled.
- Inputs: `book/examples/extract_sbs/build/profiles/{airlock,bsd,sample}.sb.bin` (plus any other stable system blobs available locally).
- Tooling: `book.api.decoder`; shared vocab and op-table mappings in `book/graph/mappings/`.
- Output: digest JSON at `book/graph/mappings/system_profiles/digests.json` with build metadata and provenance notes.

## Plan (summary)

1. Decode each curated system profile and collect op-table entries, tag counts, literals/regex, and section offsets.
2. Normalize and publish the digest under `book/graph/mappings/system_profiles/`.
3. Add a guardrail check confirming digest presence and basic fields.

## Current status

- Experiment scaffolded (this report, Plan, Notes).
- Baseline decode complete for canonical profiles; interim digest at `out/digests.json`.
- Normalized digest published to `book/graph/mappings/system_profiles/digests.json` with host metadata, op-table entries, node/tag counts, literal sample, sections, and validation flags for `airlock`, `bsd`, and `sample`.
- Guardrail added (`tests/test_mappings_guardrail.py`) to ensure digests remain present and version-tagged.

## Expected outcomes

- Reusable digest file for curated system profiles on this host/build.
- Guardrail script/test to ensure digests stay present and well-formed.
- Notes/Report updates capturing any anomalies.
