# System Profile Digest – Research Report (Sonoma baseline)

Status: **ok (structural; dispersed)**

> Archived experiment scaffold. Canonical mapping: `book/graph/mappings/system_profiles/digests.json`.

## Purpose
Produce stable digests for curated system profile blobs (for example, `airlock`, `bsd`, `sample`) using the current decoder. Each digest captures op-table buckets, tag counts, literal samples, and basic section info, and is published at `book/graph/mappings/system_profiles/digests.json` for reuse across the book.

## Baseline & scope
- World: Sonoma baseline from `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
- Inputs: `book/graph/concepts/validation/fixtures/blobs/{airlock,bsd,sample}.sb.bin` (plus any other stable system blobs added later).
- Tooling: `book.api.profile.digests` (decoder-backed); shared vocab and op-table mappings in `book/graph/mappings/`.
- Output: digest JSON at `book/graph/mappings/system_profiles/digests.json` with build metadata and provenance notes.

## Deliverables / expected outcomes
- Reusable digest file for curated system profiles on this host/build.
  - Guardrail test to ensure digests stay present and well-formed.
  - Report/Notes entries capturing any anomalies.
- Local scratch artifacts under this directory:
  - `Plan.md`, `Notes.md`, `Report.md`.
  - `out/digests.json` (intermediate per-profile summaries).

## Plan & execution log
### Completed
- **Current status**
  - Experiment scaffolded (this Report, Plan, Notes).
  - Baseline decode complete for canonical profiles; interim digest at `out/digests.json` (regenerated via `run.py`).
  - Normalized digest published to `book/graph/mappings/system_profiles/digests.json` with host metadata, op-table entries, node/tag counts, literal sample, sections, and validation flags for `airlock`, `bsd`, and `sample`.
  - Guardrail added (`tests/test_mappings_guardrail.py`) to ensure digests remain present and version-tagged.
  - Digests refreshed under the current decoder framing (stride=8 node records selected via op-table witness); contract/tag-layout hashes and canonical status are expected to stay `ok` once the mapping generator is rerun.
  - Canonical digests are now emitted by the validation job (`book/graph/concepts/validation/system_profile_experiment_job.py`) from the fixed canonical blobs; the experiment `out/` artifacts are retained for provenance only and are not consumed by mappings.
- **1) Scope and setup**
  - Identified input blobs: `book/graph/concepts/validation/fixtures/blobs/{airlock,bsd,sample}.sb.bin` on this Sonoma host.
  - Confirmed digest tooling (`book.api.profile.digests`, decoder-backed) and shared mappings (`book/graph/mappings/vocab`, `book/graph/mappings/op_table`) are available and in use.
- **2) Decode and summarize**
  - Decoded each curated system profile and captured op-table entries, node/tag counts, literal strings, and section offsets into `out/digests.json`.
- **3) Publish stable artifact**
  - Wrote the curated digest to `book/graph/mappings/system_profiles/digests.json` with version/build metadata.
  - Added provenance notes and a summary of contents to this Report and to `Notes.md`.
- **4) Guardrails**
  - Added a guardrail test (`tests/test_mappings_guardrail.py`) that asserts digest presence, host metadata, and basic fields for the curated profiles.
  - Updated `Notes.md` and `ResearchReport.md` with findings and any anomalies observed so far.

### Maintenance / rerun plan
If the digest set needs to be updated (for example, new system profiles or decoder changes), reuse this outline:

1. **Scope and setup**
   - Confirm the active baseline (OS/build, SIP) and record it in `book/world/.../world.json`, this Report, and `Notes.md` if the curated set expands.
   - Decide which additional system profiles (if any) should join the curated set.
2. **Decode and summarize**
   - Decode each curated profile and collect op-table entries, node/tag counts, literal samples, and section offsets into `out/digests.json`.
   - Refine or extend the intermediate summary format only if new profiles or decoders require additional fields.
3. **Publish and guard**
   - Normalize and publish the digest under `book/graph/mappings/system_profiles/digests.json` with updated host metadata.
   - Extend the guardrail test to cover any new curated profiles while keeping existing checks intact.

## Evidence & artifacts
- Canonical system profiles at `book/graph/concepts/validation/fixtures/blobs/{airlock,bsd,sample}.sb.bin` for this host.
- Published digest `book/graph/mappings/system_profiles/digests.json` with host metadata, op-table entries, node/tag counts, literal samples, and section offsets.
- Validation IR `book/graph/concepts/validation/out/experiments/system-profile-digest/digests_ir.json` generated directly from the canonical blobs.
- Guardrail coverage in `tests/test_mappings_guardrail.py` asserting presence and basic shape of the digests.
- Archive note: the original experiment-local scratch `out/` JSON was removed during archival; see `Examples.md` for small excerpts.

## Maintenance notes
- Digest contents reflect the current decoder’s view; if the decoder framing changes, regenerate digests and update guardrails to keep them meaningful.
- The curated set is intentionally small; only expand it via deliberate updates to the canonical profile list and mapping generator.
