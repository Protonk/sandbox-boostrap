# Report – op-coverage-and-runtime-signatures

## Purpose

This suite keeps a per-operation runtime summary aligned with the canonical promotion pipeline for this world (`world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`). The canonical output is `book/graph/mappings/runtime/op_runtime_summary.json` (mapped); this experiment no longer owns summarization logic and only mirrors the canonical summary into `out/` for convenience.

## Baseline & scope

- World: `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
- Inputs: promotable runtime packets (launchd_clean channel) from runtime-checks, runtime-adversarial, hardened-runtime, and anchor-filter-map.
- Output: per-op counts, mismatch examples, and blocked-stage tallies derived from normalized runtime events.
- Out of scope: new probe design lives in the originating experiments (primarily `book/experiments/runtime-adversarial`).

## Deliverables / expected outcomes

- `book/graph/mappings/runtime/op_runtime_summary.json` (mapped): canonical per-operation runtime summary (counts, mismatch examples, blocked-stage tallies).
- Alignment with `book/graph/mappings/runtime_cuts/ops.json` (internal runtime cuts) and the runtime signature mappings in `book/graph/mappings/runtime/runtime_signatures.json`.
- Coverage linkage via `book/graph/mappings/vocab/ops_coverage.json` (bedrock surface; see `book/graph/concepts/BEDROCK_SURFACES.json`).

## Mechanism (promotion packet -> mapping)

1. Run runtime plans via runtime and emit promotion packets:
   - `python -m book.api.runtime run --plan book/experiments/runtime-adversarial/plan.json --channel launchd_clean --out book/experiments/runtime-adversarial/out`
   - `python -m book.api.runtime emit-promotion --bundle book/experiments/runtime-adversarial/out --out book/experiments/runtime-adversarial/out/promotion_packet.json`
2. Promote runtime mappings (canonical):
   - `python book/graph/mappings/runtime/promote_from_packets.py`
   - This generates `op_runtime_summary.json` alongside runtime cuts, runtime coverage, and runtime signatures.
3. Optional mirror for this suite:
   - `python book/experiments/op-coverage-and-runtime-signatures/harvest_runtime_artifacts.py`
   - `summarize_from_adversarial.py` is a deprecated alias that also copies the canonical summary into `out/`.

## Evidence & artifacts

- Canonical summary: `book/graph/mappings/runtime/op_runtime_summary.json` (mapped).
- Related runtime mappings: `book/graph/mappings/runtime/runtime_signatures.json`, `book/graph/mappings/runtime/runtime_coverage.json`.
- Runtime cuts (derived, not canonical): `book/graph/mappings/runtime_cuts/ops.json`.
- VFS divergence context: `book/experiments/vfs-canonicalization/Report.md` (mapped; explains `/tmp` -> `/private/tmp`).
- This suite's `out/` contains historical copies and mirrors only; treat it as convenience, not a source of truth.

## Status and limits

- Evidence tier: mapped (not bedrock; bedrock surfaces are listed in `book/graph/concepts/BEDROCK_SURFACES.json`).
- Apply-stage failures remain blocked evidence; they do not imply policy semantics.
- Mismatches in file path families are expected when `/tmp` canonicalizes to `/private/tmp`; see the VFS canonicalization report for the bounded explanation.

## Next steps

- Expand runtime-adversarial probe families when new ops need runtime coverage, then rerun promotion and refresh the mapping.
- If a specific op needs a dedicated witness, add a focused probe and ensure the promotion packet is launchd_clean so it can enter the mapped summary.
