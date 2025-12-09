# Experiment suite: op-coverage-and-runtime-signatures

Purpose: establish whether the operation vocabulary, system-profile coverage, and runtime signatures line up for this world (`world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`). The suite is about linking vocab entries → profile references → runtime signatures under controlled probes.

## Evidence cards

### Per-op runtime signature alignment
- Claim: for a targeted operation `op`, the vocab entry (name/ID), the profiles that reference it, and the runtime signature observed when exercising it are consistent on this host.
- Signals: structured runtime logs showing signature S emitted only when op O is hit under profile P; op coverage counts per profile; mismatches where a signature appears without the op (or vice versa).
- IR path: normalized runtime logs land in `out/` and feed a validation job (e.g., `runtime:op-signatures`); expected to confirm or challenge `book/graph/mappings/runtime/runtime_signatures.json` and per-op coverage in `book/graph/mappings/vocab/ops_coverage.json`.

### Profile-based op coverage cross-check
- Claim: canonical/system profiles and SBPL probes reference the same operations the runtime signatures suggest, so coverage summaries are accurate for this world.
- Signals: decoded graphs showing op references; runtime traces showing which ops were actually exercised; diffs between expected and observed coverage per profile/op.
- IR path: decoded graphs from probes and logs in `out/` flow into validation output (new job) that compares against system profile digests and coverage mappings; informs whether coverage fields in mappings/CARTON need updates.

## Experimental design

- Vary: SBPL snippets and profiles designed to hit specific ops; arguments/paths/env needed to trigger those ops; which profile layers are active when running the probes.
- Hold fixed: world_id, canonical system profiles, vocab/tag-layout mappings, runtime harness configuration (containers, entitlements, apply context).
- Expected contrasts: distinct ops should produce distinct runtime signatures or op-table hits; some ops may share signatures—recording that is an explicit outcome. Ops unused in a profile should not generate signatures in that context.
- Interpretation:
  - Support: signature S appears exactly when exercising op O under profile P; coverage counts and runtime logs agree with `ops_coverage.json` and `runtime_signatures.json`.
  - Ambiguous: no signature captured despite attempts (could be gating or probe flaw).
  - Against: signature appears without op reference, or op reference never surfaces a signature when it should; indicates vocab/runtime linkage or coverage is incomplete.

## Current workflow (reuse runtime-adversarial, keep artifacts local)
- Run the adversarial harness: `python book/experiments/runtime-adversarial/run_adversarial.py`.
- Harvest the runtime outputs into this suite: `python book/experiments/op-coverage-and-runtime-signatures/harvest_runtime_artifacts.py` (copies `runtime_results.json`, `expected_matrix.json`, `mismatch_summary.json`, `impact_map.json` into `out/`).
- Summarize per-op outcomes from the local copy: `python book/experiments/op-coverage-and-runtime-signatures/summarize_from_adversarial.py` → `out/op_runtime_summary.json`.
