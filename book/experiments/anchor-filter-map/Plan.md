# Anchor ↔ Filter ID Mapping

Goal: bind anchor labels from `probe-op-structure` to concrete Filter IDs using anchor hits, `field2` inventories, and vocab artifacts; publish a reusable map at `book/graph/mappings/anchors/anchor_filter_map.json`.

---

## 1) Scope and setup

**Done**

- Host baseline (OS/build, SIP) recorded in `ResearchReport.md`.
- Inputs confirmed: `probe-op-structure/out/anchor_hits.json`, `field2-filters/out/field2_inventory.json`, vocab (`book/graph/mappings/vocab/filters.json`), anchor → field2 hints (`book/graph/mappings/anchors/anchor_field2_map.json`).
- Decoder (`book.api.decoder`) validated via existing probes and inventories.

**Upcoming**

- None for this section.

Deliverables: plan/notes/report here; `out/` for intermediate mappings.

## 2) Baseline data pass

**Done**

- Loaded anchor hits and field2 inventory; identified anchors with clear filter context (paths, mach names, iokit symbols).
- Built initial candidates for anchor → filter-ID mapping, including conflicting and ambiguous cases.

**Upcoming**

- None for this section.

Deliverables: `out/anchor_filter_candidates.json` with evidence pointers.

## 3) Targeted probes (if needed)

**Done**

- None so far; current map is based solely on existing probes and system profiles.

**Upcoming**

- Craft minimal SBPL probes to disambiguate anchors that still have multiple plausible filters.
- Decode and re-run anchor extraction; refine the candidate mapping where new evidence appears.

Deliverables: additional probe blobs (if created) and refreshed candidates.

## 4) Synthesis and guardrails

**Done**

- Finalized `book/graph/mappings/anchors/anchor_filter_map.json` with host metadata, status fields, and provenance notes per anchor.
- Added a guardrail test (`tests/test_mappings_guardrail.py`) that asserts map presence and at least one mapped anchor → filter ID.
- Updated `ResearchReport.md` and `Notes.md` with current mapping decisions, evidence sources, and remaining ambiguous anchors.

**Upcoming**

- Revisit ambiguous anchors after additional probes or decoder improvements, and extend the map accordingly.

Stop condition: anchor → filter-ID map produced with documented evidence; guardrail added; Notes/Report updated.
