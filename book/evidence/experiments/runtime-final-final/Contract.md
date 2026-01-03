# Runtime Contract Tracking

Baseline: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
Coordination: this file is the coordination surface for cross-suite runtime contracts.

## Invariant
Any derived output must be bundle-derived and stamped with `(run_id, artifact_index digest)`; no direct `out/LATEST` scraping by consumers.

## Smoke run ritual (after each big step)
1. `python -m book.api.runtime status`
2. `python -m book.api.runtime run --plan <suite>/plan.json --channel <channel>`
3. Verify committed bundle contains `artifact_index.json` and lane-scoped artifacts
4. `make -C book test`

## Suites (canonical invocations)

### metadata-runner
- invocation: `python -m book.api.runtime run --plan book/evidence/experiments/runtime-final-final/suites/metadata-runner/plan.json --channel launchd_clean --out book/evidence/experiments/runtime-final-final/suites/metadata-runner/out`
- authoritative outputs: `book/evidence/experiments/runtime-final-final/suites/metadata-runner/out/<run_id>/artifact_index.json`
- promotion packet (optional): `book/evidence/experiments/runtime-final-final/suites/metadata-runner/out/promotion_packet.json`
- downstream consumers: `book/graph/concepts/validation/metadata_runner_experiment_job.py`, `book/integration/tests/runtime/test_metadata_runner_outputs.py`

### lifecycle-lockdown
- invocation: `python3 book/evidence/experiments/runtime-final-final/suites/lifecycle-lockdown/run_lockdown.py --out book/evidence/experiments/runtime-final-final/suites/lifecycle-lockdown/out` plus runtime lane run:
  `python -m book.api.runtime run --plan book/evidence/experiments/runtime-final-final/suites/lifecycle-lockdown/plan.json --channel launchd_clean --out book/evidence/experiments/runtime-final-final/suites/lifecycle-lockdown/out/runtime/launchd_clean_enforce`
- authoritative outputs: runtime bundles under `.../out/runtime/<lane>/<run_id>/` with `artifact_index.json`

### runtime-adversarial
- invocation: `python -m book.api.runtime run --plan book/evidence/experiments/runtime-final-final/suites/runtime-adversarial/plan.json --channel launchd_clean --out book/evidence/experiments/runtime-final-final/suites/runtime-adversarial/out`
- promotion packet: `book/evidence/experiments/runtime-final-final/evidence/packets/runtime-adversarial.promotion_packet.json`
- downstream consumers: `field2-atlas`, `graph-shape-vs-semantics`, runtime mapping generators

### field2-atlas (consumer)
- invocation:
  - `PYTHONPATH=$PWD python3 book/tools/policy/ratchet/atlas_static.py`
  - `PYTHONPATH=$PWD python3 book/tools/policy/ratchet/atlas_build.py --packet book/evidence/experiments/runtime-final-final/evidence/packets/runtime-adversarial.promotion_packet.json --out-root book/evidence/experiments/field2-final-final/field2-atlas/out/derived`
- authoritative outputs: `field2-atlas/out/derived/<run_id>/...` with `consumption_receipt.json`

### graph-shape-vs-semantics (consumer)
- invocation:
  - `python3 book/evidence/experiments/runtime-final-final/suites/graph-shape-vs-semantics/summarize_struct_variants.py --packet book/evidence/experiments/runtime-final-final/evidence/packets/runtime-adversarial.promotion_packet.json --out-root book/evidence/experiments/runtime-final-final/evidence/derived/graph-shape-vs-semantics`
- authoritative outputs: derived summary + receipt under `evidence/derived/graph-shape-vs-semantics/<run_id>/`
