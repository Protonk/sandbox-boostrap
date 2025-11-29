# Anchor ↔ Filter ID Mapping – Notes

Use this file for dated, concise notes on progress, commands, and intermediate findings.

## 2025-12-10

- Experiment scaffolded (plan/report/notes). Goal: convert anchor hits into a filter-ID map, landing at `book/graph/mappings/anchors/anchor_filter_map.json`. No data pass yet.

## 2025-12-11

- Baseline data pass: loaded `probe-op-structure/out/anchor_hits.json` and harvested anchors with field2 hints; wrote initial candidates to `out/anchor_filter_candidates.json` (anchor → {field2_names, field2_values, sources}). Field2 inventory not yet merged; next step is disambiguation and mapping to filter IDs.
- Produced first `anchor_filter_map.json` in `book/graph/mappings/anchors/` by mapping single-name anchors to filter IDs (`/var/log` → ipc-posix-name=4, `idVendor` → local-name=6, `preferences/logging` → global-name=5); multi-name anchors remain `status: ambiguous` with candidate filters listed.
- Guardrail added via `tests/test_mappings_guardrail.py` to ensure anchor-filter map presence and at least one mapped entry.
