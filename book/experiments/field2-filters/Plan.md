# Field2 ↔ Filter Mapping Experiment (Sonoma host)

Goal: map decoder `field2` values to Filter IDs using the harvested filter vocabulary and targeted SBPL probes, then validate consistency across operations and profiles.

---

## 1) Scope and setup

- [ ] Record host baseline (OS/build, kernel, SIP) in `ResearchReport.md`.
- [ ] Confirm vocab artifacts (`validation/out/vocab/filters.json`, `ops.json`) are `status: ok`.
- [ ] Identify canonical blobs for cross-check: `examples/extract_sbs/build/profiles/airlock.sb.bin`, `bsd.sb.bin`, `sample.sb.bin`.

Deliverables:
- `Plan.md`, `Notes.md`, `ResearchReport.md` in this directory.
- A small helper script to collect `field2` values from decoded profiles.

## 2) Baseline inventory

- [ ] Decode canonical blobs and tally unique `field2` values per node tag; record which op-table entries reach which `field2` values (via graph walks).
- [ ] Compare observed `field2` ranges to the filter vocab ID range (0..N-1).

Deliverables:
- Intermediate JSON/notes summarizing `field2` histograms and per-op reachable values.

## 3) Synthetic single-filter probes

- [ ] Author tiny SBPL profiles, each exercising exactly one filter (e.g., `subpath`, `literal`, `global-name`, `local-name`, `vnode-type`, `socket-domain`, `iokit-registry-entry-class`).
- [ ] Compile and decode each; walk from relevant op entry and record `field2` values.
- [ ] Add combination probes (require-any/require-all) to see if meta-filters affect `field2` assignment.

Deliverables:
- `sb/` variants + compiled blobs under `sb/build/`.
- Notes mapping filter name → observed `field2` value(s) with provenance.

## 4) Cross-op consistency checks

- [ ] For filters appearing in multiple operations (e.g., path filters across `file-read*`/`file-write*`, `global-name` across mach/socket), verify `field2` is consistent across ops.
- [ ] Flag any discrepancies for further probing.

Deliverables:
- Table of filter → `field2` with cross-op status (consistent/inconsistent).

## 5) System profile cross-check

- [ ] Inspect selected system profiles (from cache) where literals indicate filter type (e.g., paths, mach names) and confirm matching `field2` IDs.

Deliverables:
- Notes tying system-profile nodes to the inferred mapping.

## 6) Synthesis and guardrails

- [ ] Summarize inferred `field2` ↔ filter-ID mapping with evidence (probes and system blobs).
- [ ] Add a small test or script to assert expected `field2` for key filters (subpath, literal, global-name, local-name) against the synthetic profiles.
- [ ] Update `ResearchReport.md` with findings and open questions.

Deliverables:
- Updated `ResearchReport.md` and `Notes.md`.
- Guardrail test/script to prevent regressions.
