# Experiment suite: op-coverage-and-runtime-signatures

Purpose: link operation vocabulary entries, profile coverage, and runtime signatures for this world (`world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`). The canonical per-operation runtime summary is `book/graph/mappings/runtime/op_runtime_summary.json` (mapped); this suite's `out/` holds convenience copies only.

## Evidence cards

### Per-op runtime signature alignment
- Claim: for a targeted operation `op`, the vocab entry (name/id), the profiles that reference it, and the runtime signature observed when exercising it are consistent on this host.
- Signals: runtime logs + promotion packets showing signature S when op O is hit under profile P; per-op summaries highlighting mismatches.
- IR path: promotion packets feed runtime mapping generators, producing `book/graph/mappings/runtime/op_runtime_summary.json` and `book/graph/mappings/runtime/runtime_signatures.json`.

### Profile-based op coverage cross-check
- Claim: canonical/system profiles and SBPL probes reference the same operations the runtime signatures suggest, so coverage summaries are accurate for this world.
- Signals: decoded graphs showing op references; runtime traces showing which ops were actually exercised; diffs between expected and observed coverage per profile/op.
- IR path: mappings flow into `book/graph/mappings/vocab/ops_coverage.json` and CARTON indexes; this suite only mirrors the canonical results.

## Current workflow (promotion packet based)
- Run a runtime plan via runtime:
  `python -m book.api.runtime run --plan book/experiments/runtime-adversarial/plan.json --channel launchd_clean --out book/experiments/runtime-adversarial/out`
- Emit a promotion packet:
  `python -m book.api.runtime emit-promotion --bundle book/experiments/runtime-adversarial/out --out book/experiments/runtime-adversarial/out/promotion_packet.json`
- Promote runtime mappings (canonical):
  `python book/graph/mappings/runtime/promote_from_packets.py`
- Optional convenience copy for this suite:
  `python book/experiments/op-coverage-and-runtime-signatures/harvest_runtime_artifacts.py`
  (`summarize_from_adversarial.py` is a deprecated alias that also copies the canonical summary into `out/`).
