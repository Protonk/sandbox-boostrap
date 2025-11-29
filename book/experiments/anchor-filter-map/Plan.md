# Anchor ↔ Filter ID Mapping

Goal: bind anchor labels from `probe-op-structure` to concrete Filter IDs using anchor hits, `field2` inventories, and vocab artifacts; publish a reusable map at `book/graph/mappings/anchors/anchor_filter_map.json`.

---

## 1) Scope and setup

- [ ] Record host baseline (OS/build, SIP) in `ResearchReport.md`.
- [ ] Confirm inputs: `probe-op-structure/out/anchor_hits.json`, `field2-filters/out/field2_inventory.json`, vocab (`book/graph/mappings/vocab/filters.json`), anchor → field2 hints (`book/graph/mappings/anchors/anchor_field2_map.json`).
- [ ] Ensure decoder (`book.api.decoder`) is available for any new probes.

Deliverables: plan/notes/report here; `out/` for intermediate mappings.

## 2) Baseline data pass

- [x] Load anchor hits and field2 inventory; identify anchors with clear filter context (path literals, mach names, vnode hints).
- [x] Build initial candidates for anchor → filter-ID mapping, noting conflicts or ambiguity.

Deliverables: `out/anchor_filter_candidates.json` with evidence pointers.

## 3) Targeted probes (if needed)

- [ ] Craft minimal SBPL probes to disambiguate anchors that have multiple plausible filters.
- [ ] Decode and re-run anchor extraction; update candidate mapping.

Deliverables: additional probe blobs (if created) and refreshed candidates.

## 4) Synthesis and guardrails

- [ ] Finalize `book/graph/mappings/anchors/anchor_filter_map.json` with provenance notes.
- [x] Add a small guardrail test/script that checks a few high-confidence anchor → filter mappings against reference blobs.
- [ ] Update `ResearchReport.md` with decisions, evidence, and open questions.

Stop condition: anchor → filter-ID map produced with documented evidence; guardrail added; Notes/Report updated.
