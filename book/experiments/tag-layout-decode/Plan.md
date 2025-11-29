# Tag Layout Decode (literal/regex operands)

Goal: decode tag layouts for nodes that carry literal/regex operands, align them with decoder fields, and publish a reusable map at `book/graph/mappings/tag_layouts/tag_layouts.json`.

---

## 1) Scope and setup

**Done**

- Identified reference blobs: canonical system profiles (`airlock.sb.bin`, `bsd.sb.bin`, `sample.sb.bin`) and shared mappings needed for decoding.
- Confirmed decoder path (`book.api.decoder`) and access to `book/graph/mappings/vocab` and `book/graph/mappings/op_table`.

**Upcoming**

- Make host baseline (OS/build, SIP, decoder version) explicit in `ResearchReport.md` if tag layouts are extended or revised.

Deliverables: `Plan.md`, `Notes.md`, `ResearchReport.md` in this directory; `out/` folder for scratch JSON/histograms.

## 2) Baseline decode and tag histogram

**Done**

- Decoded reference blobs; captured node tag histograms, literal pool offsets, and basic section information in `out/tag_histogram.json`.

**Upcoming**

- Refine notes on which tags show literal or regex indices and any sentinel/padding patterns as decoding improves.

Deliverables: `out/tag_histogram.json` (or similar) with tag → counts, literal/regex usage.

## 3) Tag layout reconstruction

**Done**

- For tags that carry literal/regex operands, mapped field positions (edges vs payloads) using literal tables on canonical profiles and wrote initial layouts.

**Upcoming**

- Use anchors from `probe-op-structure` and shared vocab/op-table mappings to refine tag layouts and detect reused structures across operations.

Deliverables: draft `tag_layouts.json` (per-tag layout description) plus short notes on evidence.

## 4) Synthesis and guardrails

**Done**

- Finalized `book/graph/mappings/tag_layouts/tag_layouts.json` with per-tag field sizes, edge fields, and payload fields for literal-bearing tags, plus host metadata.
- Added guardrail tests (`tests/test_mappings_guardrail.py`) that assert presence and basic shape of the tag layout mapping.
- Updated `ResearchReport.md` and `Notes.md` to describe current layouts and how they are used by the decoder.

**Upcoming**

- Revisit layouts if new tags or operand types surface in future experiments.

Stop condition: tag layouts for literal/regex-bearing nodes validated across reference blobs and probes; reusable map committed; guardrail in place.
