# Tag Layout Decode (literal/regex operands)

Goal: decode tag layouts for nodes that carry literal/regex operands, align them with decoder fields, and publish a reusable map at `book/graph/mappings/tag_layouts/tag_layouts.json`.

---

## 1) Scope and setup

- [ ] Record host baseline (OS/build, SIP, decoder version) in `ResearchReport.md`.
- [ ] Confirm decoder path (`book.api.decoder`) and shared mappings (`book/graph/mappings/vocab`, `book/graph/mappings/op_table`) are in place.
- [ ] Identify reference blobs: canonical system profiles (`airlock.sb.bin`, `bsd.sb.bin`, `sample.sb.bin`) and probe outputs (`probe-op-structure`).

Deliverables: `Plan.md`, `Notes.md`, `ResearchReport.md` in this directory; `out/` folder for scratch JSON/histograms.

## 2) Baseline decode and tag histogram

- [x] Decode reference blobs; capture node tag histograms, literal/regex pool offsets, and any anchor hits.
- [ ] Note which tags show literal or regex indices (`literal_pool`, `regex`) and whether padding/sentinels appear.

Deliverables: `out/tag_histogram.json` (or similar) with tag → counts, literal/regex usage.

## 3) Tag layout reconstruction

- [x] For tags that carry literal/regex operands, map field positions (`fields[0..2]`, edges) and interpret operands using the literal/regex tables (best-effort).
- [ ] Use anchors from `probe-op-structure` to bind specific nodes to SBPL constructs.
- [ ] Cross-check against `field2`/filter vocab and op-table buckets to detect reused layouts.

Deliverables: draft `tag_layouts.json` (per-tag layout description) plus short notes on evidence.

## 4) Synthesis and guardrails

- [x] Finalize `book/graph/mappings/tag_layouts/tag_layouts.json` with per-tag field names, operand types, and provenance notes.
- [x] Add a small guardrail test or script that decodes reference blobs and asserts expected literal/regex placements for a few tags.
- [ ] Update `ResearchReport.md` with findings, open questions, and links to artifacts.

Stop condition: tag layouts for literal/regex-bearing nodes validated across reference blobs and probes; reusable map committed; guardrail in place.
