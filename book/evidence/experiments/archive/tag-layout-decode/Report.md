# Tag Layout Decode – Research Report

Status: **ok (structural; dispersed)**

> Archived experiment scaffold. Canonical mapping: `book/integration/carton/bundle/relationships/mappings/tag_layouts/tag_layouts.json`.

## Purpose
Map node tags that reference literal or regex pools to interpretable layouts (edge fields plus operand fields) using the current decoder and anchor hits. Produce a reusable map at `book/integration/carton/bundle/relationships/mappings/tag_layouts/tag_layouts.json` for other tooling and book chapters.

## Baseline & scope
- World: Sonoma baseline from `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
- Inputs: canonical system profiles (`book/evidence/graph/concepts/validation/fixtures/blobs/{airlock,bsd,sample}.sb.bin`), probe outputs from `probe-op-structure`, and shared vocab/op-table mappings in `book/integration/carton/bundle/relationships/mappings/`.
- Tooling: `book.api.profile.decoder` for profile decoding; anchor hints from `book/integration/carton/bundle/relationships/mappings/anchors/anchor_field2_map.json`.
- Target artifact: `book/integration/carton/bundle/relationships/mappings/tag_layouts/tag_layouts.json` (per-tag layout with operand interpretation and provenance).

## Deliverables / expected outcomes
- A per-tag layout map for literal/regex-bearing nodes with evidence trails.
  - Guardrail test that asserts expected literal/regex placements on reference blobs.
  - Updated Notes and Plan with any deviations or open questions.
- Local artifacts:
  - `Plan.md`, `Notes.md`, `Report.md` in this directory; `out/` folder for scratch JSON/histograms.
  - `out/tag_histogram.json` (or similar) with tag → counts, literal/regex usage.
  - `out/tag_literal_nodes.json` plus `tag_layouts.json` (per-tag layout description) and short notes on evidence.

## Plan & execution log
### Completed
- **Current status**
  - Experiment scaffolded (this Report, Plan, Notes).
  - Baseline decode complete for canonical system profiles (`airlock`, `bsd`, `sample`); tag counts and literal counts recorded in `out/tag_histogram.json`. Decoder inputs: `book/evidence/graph/concepts/validation/fixtures/blobs/{airlock,bsd,sample}.sb.bin`.
  - Sample literal-bearing nodes grouped by tag captured in `out/tag_literal_nodes.json` to support layout interpretation.
  - Canonical tag layouts published at `book/integration/carton/bundle/relationships/mappings/tag_layouts/tag_layouts.json` (record_size_bytes=8) and enforced by a guardrail (`book/tests/test_mappings_guardrail.py`). The decoder selects stride=8 for this world using op-table word-offset alignment evidence and exposes that witness under `validation.node_stride_selection`.
  - Canonical layouts are now emitted via `book/integration/carton/mappings/tag_layouts/generate_tag_layouts.py` from the canonical profile digests; experiment `out/` artifacts remain as provenance only.
- **1) Scope and setup**
  - Identified reference blobs: canonical system profiles (`airlock.sb.bin`, `bsd.sb.bin`, `sample.sb.bin`) and shared mappings needed for decoding.
  - Confirmed decoder path (`book.api.profile.decoder`) and access to `book/integration/carton/bundle/relationships/mappings/vocab` and `book/integration/carton/bundle/relationships/mappings/op_table`.
- **2) Baseline decode and tag histogram**
  - Decoded reference blobs; captured node tag histograms, literal pool offsets, and basic section information in `out/tag_histogram.json`.
- **3) Tag layout reconstruction**
  - For tags that carry literal/regex operands, mapped field positions (edges vs payloads) using literal tables on canonical profiles and wrote initial layouts.
- **4) Synthesis and guardrails**
  - Finalized `book/integration/carton/bundle/relationships/mappings/tag_layouts/tag_layouts.json` with per-tag field sizes, edge fields, and payload fields for literal-bearing tags, plus host metadata.
  - Added guardrail tests (`tests/test_mappings_guardrail.py`) that assert presence and basic shape of the tag layout mapping.
  - Updated `ResearchReport.md` and `Notes.md` to describe current layouts and how they are used by the decoder.

### Maintenance / rerun plan
If tag layouts need to be extended or revised, reuse this outline:

1. **Scope and setup**
   - Confirm the baseline (OS/build, SIP, decoder version) and record it in `book/world/.../world.json`, this Report, and `Notes.md` when layouts change.
   - Identify additional reference blobs or probe outputs that should be included.
2. **Baseline decode and tag histogram**
   - Decode reference blobs; refresh tag histograms, literal usage, and any sentinel/padding patterns into `out/tag_histogram.json`.
3. **Tag layout reconstruction**
   - Use anchors from `probe-op-structure` and shared vocab/op-table mappings to refine tag layouts and detect reused structures across operations.
   - Update `out/tag_literal_nodes.json` as needed.
4. **Synthesis and guardrails**
   - Refresh `tag_layouts.json` with new or adjusted per-tag layouts.
   - Keep guardrail tests in `tests/test_mappings_guardrail.py` in sync so they continue to assert presence and basic shape of the mapping.

## Evidence & artifacts
- Reference blobs `airlock.sb.bin`, `bsd.sb.bin`, and `sample.sb.bin` decoded via `book.api.profile.decoder`.
- Published tag-layout map `book/integration/carton/bundle/relationships/mappings/tag_layouts/tag_layouts.json` plus associated guardrail tests in `tests/test_mappings_guardrail.py`.
- Archive note: the original scratch `out/` JSONs were removed during archival; see `Examples.md` for small excerpts.

## Maintenance notes
- Tag layouts are defined for the canonical corpus on this world; adding new tags or operand types should be treated as a new, explicit extension (not a silent drift).
- Layout interpretations rely on the current decoder and literal-table heuristics; if those change, rerun the generator and guardrails to keep `tag_layouts.json` aligned.
