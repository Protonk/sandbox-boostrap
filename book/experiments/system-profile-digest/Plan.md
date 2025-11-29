# System Profile Digest

Goal: decode curated system profile blobs and produce reusable digests (op-table buckets, tag counts, literals) stored at `book/graph/mappings/system_profiles/digests.json`.

---

## 1) Scope and setup

- [ ] Record host baseline (OS/build, SIP) in `ResearchReport.md`.
- [ ] Confirm decoder path (`book.api.decoder`) and shared mappings (`book/graph/mappings/vocab`, `book/graph/mappings/op_table`) are available.
- [ ] Identify input blobs: `book/examples/extract_sbs/build/profiles/{airlock,bsd,sample}.sb.bin` (and any other stable system profiles on this host).

Deliverables: plan/notes/report here; `out/` for scratch outputs.

## 2) Decode and summarize

- [x] Decode each system profile; capture op-table entries, tag counts, node counts, literal/regex strings, and section offsets.
- [ ] Normalize outputs into a digestable summary format.

Deliverables: `out/digests.json` (intermediate) with per-profile summaries.

## 3) Publish stable artifact

- [x] Write the curated digest to `book/graph/mappings/system_profiles/digests.json` with version/build metadata.
- [x] Add brief provenance notes in `ResearchReport.md`.

## 4) Guardrails

- [x] Add a small guardrail test/script that asserts digest presence and basic fields for the curated profiles.
- [ ] Update `Notes.md` and `ResearchReport.md` with findings and any deltas.

Stop condition: curated system profile digests published to `book/graph/mappings/system_profiles/digests.json` with guardrail coverage.
