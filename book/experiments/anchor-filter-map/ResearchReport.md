# Anchor ↔ Filter ID Mapping – Research Report (Sonoma / macOS 14.4.1)

## Purpose

Bind anchor labels emitted by `probe-op-structure` to concrete Filter IDs, using anchor hits, `field2` inventories, and vocab artifacts. The resulting map (`book/graph/mappings/anchors/anchor_filter_map.json`) should let other tools interpret anchors in terms of filter semantics.

## Baseline and scope

- Host: macOS 14.4.1 (23E224), Apple Silicon, SIP enabled.
- Inputs:
  - Anchor hits from `book/experiments/probe-op-structure/out/anchor_hits.json`.
  - Field2 inventory (with anchors) from `book/experiments/field2-filters/out/field2_inventory.json`.
  - Filter vocab from `book/graph/mappings/vocab/filters.json`.
  - Existing anchor → field2 hints from `book/graph/mappings/anchors/anchor_field2_map.json`.
- Tooling: `book.api.decoder` for any new probes; existing probe outputs as primary evidence.
- Target artifact: `book/graph/mappings/anchors/anchor_filter_map.json` with provenance notes.

## Plan (summary)

1. Baseline pass over existing anchor hits and field2 inventory to propose anchor → filter-ID candidates.
2. Craft targeted probes if needed to disambiguate anchors with multiple plausible filters.
3. Synthesize a stable map with evidence and add guardrail checks on reference blobs.

## Current status

- Experiment scaffolded (this report, Plan, Notes).
- Baseline candidate extraction done: `out/anchor_filter_candidates.json` holds anchor → {field2_names, field2_values, sources}.
- First pass map published at `book/graph/mappings/anchors/anchor_filter_map.json`: single-name anchors mapped to filter IDs (`/var/log` → ipc-posix-name=4, `idVendor` → local-name=6, `preferences/logging` → global-name=5); multi-name anchors remain `status: ambiguous` with candidate filters listed. Further disambiguation remains. Guardrail added (`tests/test_mappings_guardrail.py`) to ensure map presence and mapped entries.

## Expected outcomes

- Anchor → filter-ID map with evidence references.
- Guardrail script/test covering a few high-confidence anchors.
- Updated Notes/Plan reflecting any deviations or unresolved anchors.
