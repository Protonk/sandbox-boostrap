# Field2 ↔ Filter Mapping Experiment (Sonoma host)

Goal: map decoder `field2` values to Filter IDs using the harvested filter vocabulary and targeted SBPL probes, then validate consistency across operations and profiles.

---

## 1) Scope and setup

**Done**

- Host baseline (OS/build, kernel, SIP) and canonical blobs recorded in `ResearchReport.md`.
- Vocab artifacts (`book/graph/mappings/vocab/filters.json`, `ops.json`) confirmed `status: ok` (93 filters, 196 ops).
- Canonical blobs for cross-check identified and used: `book/examples/extract_sbs/build/profiles/airlock.sb.bin`, `bsd.sb.bin`, `sample.sb.bin`.

**Upcoming**

- Keep baseline/version notes updated if the host or vocab artifacts change.

Deliverables:
- `Plan.md`, `Notes.md`, `ResearchReport.md` in this directory.
- A small helper script to collect `field2` values from decoded profiles.

## 2) Baseline inventory

**Done**

- Decoded canonical blobs and tallied unique `field2` values; baseline histograms recorded in `ResearchReport.md` and `Notes.md`.
- Confirmed that many `field2` values align directly with filter vocab IDs (e.g., path/socket/iokit filters in `bsd` and `sample`), with high unknowns in `airlock`.

**Upcoming**

- Refine per-tag/per-op inventories using newer decoder layouts if needed.

Deliverables:
- Intermediate JSON/notes summarizing `field2` histograms and per-op reachable values.

## 3) Synthetic single-filter probes

**Done**

- Authored single-filter SBPL variants (subpath, literal, global-name, local-name, vnode-type, socket-domain, iokit-registry-entry-class, require-any mixtures) and compiled them under `sb/build/`.
- Decoded each variant and recorded `field2` values; synthesized into `out/field2_inventory.json`.

**Upcoming**

- Design additional probes that reduce generic path/name scaffolding (e.g., richer operations or more complex metafilters) if needed to surface filter-specific `field2` values.

Deliverables:
- `sb/` variants + compiled blobs under `sb/build/`.
- Notes mapping filter name → observed `field2` value(s) with provenance.

## 4) Cross-op consistency checks

**Done (initial)**

- Checked that low `field2` IDs corresponding to path/name filters (0,1,3,4,5,6,7,8) behave consistently across system profiles and synthetic probes.
- Confirmed that system profiles (`bsd`, `sample`) reinforce the mapping for common filters (preference-domain, right-name, iokit-*, path/socket).

**Upcoming**

- Perform focused cross-op checks for less common filters once better probes or anchors are available.
- Flag and investigate any inconsistencies that appear as decoding improves.

Deliverables:
- Table of filter → `field2` with cross-op status (consistent/inconsistent).

## 5) System profile cross-check

**Done (baseline)**

- Inspected curated system profiles where literals strongly indicate filter type (paths, mach names, iokit properties) and confirmed that `field2` IDs match vocab entries where known.

**Upcoming**

- Use anchor mappings and updated tag layouts to deepen system-profile cross-checks, especially for high, currently-unknown `field2` values in `airlock`.

Deliverables:
- Notes tying system-profile nodes to the inferred mapping.

## 6) Synthesis and guardrails

**Done (partial)**

- Summarized current understanding of `field2` behavior (generic path/name dominance, confirmed mappings for common filters, persistence of unknowns) in `ResearchReport.md` and `Notes.md`.
- Regenerated `out/field2_inventory.json` using shared tag layouts and anchor/filter mappings to keep inventories aligned with the global IR.

**Upcoming**

- Distill a stable `field2` ↔ filter-ID table for a small, high-confidence subset of filters.
- Add a guardrail test/script that checks these mappings against synthetic profiles.
- Extend `ResearchReport.md` with any newly established mappings and explicit open questions.

Deliverables:
- Updated `ResearchReport.md` and `Notes.md`.
- Guardrail test/script to prevent regressions.
