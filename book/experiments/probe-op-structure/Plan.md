# Probe Op Structure Experiment (Sonoma host)

Goal: design and run a set of SBPL probes with richer, varied structure to extract clearer mappings between operations, filters (and their `field2` encodings), and op-table behavior. This experiment should complement the field2-focused work by using more complex profiles (multiple filters, layered ops) to surface filter-specific nodes beyond the generic path/name scaffolding.

---

## 1) Scope and setup

**Done**

- Confirmed vocab artifacts (`graph/mappings/vocab/ops.json`, `filters.json`) are `status: ok`.
- Identified prior experiments (`field2-filters`, `op-table-operation`, `node-layout`) as upstream context for this probe work.

**Upcoming**

- Make the host baseline (OS/build, kernel, SIP) explicit in `ResearchReport.md` as this experiment evolves.

Deliverables:
- `Plan.md`, `Notes.md`, `ResearchReport.md` in this directory.
- A structured probe matrix describing intended SBPL variants.

## 1.5) Per-tag inventory (sanity pass)

**Done (initial)**

- Performed coarse tag/stride inventories across probe and system profiles (see `tag_inventory` outputs) to sanity-check slicing.

**Upcoming**

- Extend the per-tag inventory once richer tag layouts are available from the tag-layout-decode experiment.

Deliverables:
- Notes on tag byte counts/stride candidates in `Notes.md`; brief summary in `ResearchReport.md`.

## 2) Improve slicing/decoding

**Done**

- Added segment-aware slicing fallbacks in shared ingestion/decoder code to recover node regions for complex profiles that previously yielded `node_count=0`.

**Upcoming**

- Continue to track when fallbacks are used and adjust heuristics as new profile shapes appear.

Deliverables:
- Updated helper script(s) for slicing/decoding richer profiles; note usage in `Notes.md`.

## 3) Anchor-based traversal

**Done (baseline)**

- Implemented anchor scanning over decoded literal strings and offsets; anchors now resolve to literal offsets and, for simple probes, to node indices via `literal_refs`.

**Upcoming**

- Improve tag-aware decoding so anchor-bound nodes can be interpreted reliably in terms of Filters and field2.

Deliverables:
- JSON or notes tying anchor literals → node indices → `field2` → inferred filter.

## 4) Probe design (anchor-aware)

**Done (initial)**

- Designed and implemented an initial probe matrix (file require-all/any, mach global/local, network socket, iokit class/property, and mixed combos) with distinct anchors.

**Upcoming**

- Refine probes to maximize anchor separation and reduce generic path/name masking once node decoding improves.

Deliverables:
- Updated probe matrix in `Notes.md` reflecting anchor choices.

## 5) Compilation and decoding

**Done**

- Authored SBPL profiles per the initial anchor-aware matrix, compiled them via `libsandbox`, and decoded them with updated slicing.
- Collected op-table behavior, field2 histograms, and anchor-based node hits in experiment outputs.

**Upcoming**

- Recompile/redecode only if new probes or decoder changes warrant it.

Deliverables:
- `sb/` sources and compiled blobs; updated summaries including anchor-based findings.

## 6) Analysis and mapping

**Done (initial)**

- Used anchor hits and field2 inventories to confirm that generic path/name filters dominate small profiles and to motivate tag-aware decoding.
- Began forming tag-specific layout hypotheses and literal/regex correlation strategies, feeding into the tag-layout-decode experiment.

**Upcoming**

- Perform a focused analysis of anchor-derived field2 values once node layouts and literal bindings are better understood.
- Triangulate with system profiles and refine hypotheses into concrete mappings.

Deliverables:
- Updated `ResearchReport.md` with provisional mappings, evidence tiers, and structural notes.

## 7) Guardrails and reuse

**Upcoming**

- Once stable mappings exist, add a checker that locates anchor literals in probe blobs and asserts expected `field2` values.
- Document how these probes can be reused by other experiments (field2 mapping, op-table alignment) and add guardrail tests accordingly.
