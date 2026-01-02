# Field2 Final Final — Research Report

Status: partial

## Purpose
Provide a single, unified experiment surface for field2 on the Sonoma baseline. This experiment consolidates static field2 inventories, anchor/tag structural scans, encoder emission witnesses, targeted probe suites, and runtime-backed atlas construction into one reproducible pipeline.

## Position in the repo
This is the only active field2 experiment. It replaces the previous field2-focused experiments and is now the canonical location for all field2 evidence within `book/experiments/`.

## Structure
The experiment is organized as submodules under this root:
- `field2-filters/` — inventories and unknown census.
- `field2-atlas/` — static+runtime atlas outputs with packet-only consumption.
- `probe-op-structure/` — anchor/tag/field2 structural scans.
- `anchor-filter-map/` — runtime discriminator matrices for anchor→filter bindings.
- `libsandbox-encoder/` — encoder matrices and byte-level network witnesses.
- `flow-divert-2560/` — triple-token characterization.
- `bsd-airlock-highvals/` — high/opaque payload probes.

## Evidence paths (canonical)
- Inventory: `book/experiments/field2-final-final/field2-filters/out/field2_inventory.json`.
- Unknown census: `book/experiments/field2-final-final/field2-filters/out/unknown_nodes.json`.
- Anchor hits: `book/experiments/field2-final-final/probe-op-structure/out/anchor_hits.json`.
- Atlas static: `book/experiments/field2-final-final/field2-atlas/out/static/field2_records.jsonl`.
- Atlas derived: `book/experiments/field2-final-final/field2-atlas/out/derived/<run_id>/...`.

## Current status
- Static inventories are current for the seed slice and the high/unknown census.
- Runtime atlas remains partial and depends on promotion packets from runtime-adversarial and anchor-filter-map; packet-only consumption is enforced.
- Encoder matrices and flow-divert triple-only witnesses are preserved as static, structural evidence.

## Notes on scope and limits
- All claims are host-bound to the Sonoma baseline and require explicit evidence tiering.
- Apply-stage failures remain `blocked` and are not treated as policy semantics.
- This experiment does not change mappings directly; it produces evidence that can be promoted through the standard validation → mappings pipeline.
