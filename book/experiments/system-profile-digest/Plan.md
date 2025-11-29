# System Profile Digest

Goal: decode curated system profile blobs and produce reusable digests (op-table buckets, tag counts, literals) stored at `book/graph/mappings/system_profiles/digests.json`.

---

## 1) Scope and setup

**Done**

- Identified input blobs: `book/examples/extract_sbs/build/profiles/{airlock,bsd,sample}.sb.bin` on this Sonoma host.
- Confirmed decoder path (`book.api.decoder`) and shared mappings (`book/graph/mappings/vocab`, `book/graph/mappings/op_table`) are available and in use.

**Upcoming**

- Make the host baseline (OS/build, SIP) explicit in `ResearchReport.md` if the digest set expands.

Deliverables: plan/notes/report here; `out/` for scratch outputs.

## 2) Decode and summarize

**Done**

- Decoded each curated system profile and captured op-table entries, node/tag counts, literal strings, and section offsets into `out/digests.json`.

**Upcoming**

- Refine or extend the intermediate summary format only if new profiles or decoders require additional fields.

Deliverables: `out/digests.json` (intermediate) with per-profile summaries.

## 3) Publish stable artifact

**Done**

- Wrote the curated digest to `book/graph/mappings/system_profiles/digests.json` with version/build metadata.
- Added provenance notes and a summary of contents to `ResearchReport.md` and `Notes.md`.

## 4) Guardrails

**Done**

- Added a guardrail test (`tests/test_mappings_guardrail.py`) that asserts digest presence, host metadata, and basic fields for the curated profiles.
- Updated `Notes.md` and `ResearchReport.md` with findings and any anomalies observed so far.

**Upcoming**

- Extend guardrails or digests if additional system profiles are added in future.

Stop condition: curated system profile digests published to `book/graph/mappings/system_profiles/digests.json` with guardrail coverage.
