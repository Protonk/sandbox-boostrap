# Anchor ↔ Filter Runtime Discriminators — Plan

## Purpose
Host-bound runtime discriminator suite that supports the anchor → Filter ID mapping in `field2-final-final/anchor-filter-map`. This suite only covers runtime plans, registries, SBPL, and bundles; mapping synthesis remains in the field2 experiment.

## Baseline & scope
- World: `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
- Runtime channel: `launchd_clean` for decision-stage evidence.
- Outputs: runtime bundles and promotion packets only; mapping updates are handled by field2.

## Execution
- Run: `python -m book.api.runtime run --plan book/experiments/runtime-final-final/suites/anchor-filter-map/plan.json --channel launchd_clean --out book/experiments/runtime-final-final/suites/anchor-filter-map/out`
- Emit packet: `python -m book.api.runtime emit-promotion --bundle book/experiments/runtime-final-final/suites/anchor-filter-map/out/LATEST --out book/experiments/runtime-final-final/evidence/packets/anchor-filter-map.promotion_packet.json`
