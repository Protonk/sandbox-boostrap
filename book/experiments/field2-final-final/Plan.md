# Field2 Final Final — Plan

## Purpose
Consolidate all field2-related work into a single experiment root, keep evidence paths stable, and preserve a coherent static→runtime→atlas pipeline on the Sonoma host baseline.

## Baseline & scope
- World: `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
- Scope: structural field2 extraction, anchor/tag layout, encoder emission, focused probe suites, and runtime-atlas joins.
- Out of scope: cross-world claims and any mapping edits outside the standard promotion flow.

## Layout (canonical submodules)
- `field2-filters/` — field2 inventories + unknown census + libsandbox Scheme extraction.
- `field2-atlas/` — static+runtime atlas builder and derived outputs.
- `probe-op-structure/` — anchor/tag/field2 structural scans and anchor hits.
- `anchor-filter-map/` — runtime discriminator matrices for anchor→filter bindings.
- `libsandbox-encoder/` — SBPL→blob encoder matrices and network-arg byte witnesses.
- `flow-divert-2560/` — flow-divert triple token characterization.
- `bsd-airlock-highvals/` — high/opaque field2 payload probes.

## Expected evidence paths (stable)
- Inventory: `book/experiments/field2-final-final/field2-filters/out/field2_inventory.json`.
- Unknown census: `book/experiments/field2-final-final/field2-filters/out/unknown_nodes.json`.
- Anchor hits: `book/experiments/field2-final-final/probe-op-structure/out/anchor_hits.json`.
- Anchor candidates: `book/experiments/field2-final-final/anchor-filter-map/out/anchor_filter_candidates.json`.
- Atlas static: `book/experiments/field2-final-final/field2-atlas/out/static/field2_records.jsonl`.
- Atlas derived: `book/experiments/field2-final-final/field2-atlas/out/derived/<run_id>/...`.
- Flow-divert matrix: `book/experiments/field2-final-final/flow-divert-2560/out/matrix_records.jsonl`.
- Encoder network matrix: `book/experiments/field2-final-final/libsandbox-encoder/out/network_matrix/*`.

## Execution paths
- Static pipeline: run the field2 validation job after refreshing local experiment outputs.
- Runtime pipeline: run plan-based probes via `python -m book.api.runtime run --plan ... --channel launchd_clean` and consume promotion packets in atlas builders.
- Atlas build: run `field2-atlas/atlas_build.py --packet <promotion_packet.json> --out-root <dir>`.

## Guardrails
- Treat apply-stage failures as `blocked` evidence; use preflight before runtime probes.
- All derived outputs must be bundle-derived and provenance stamped with `(run_id, artifact_index sha256)`.
