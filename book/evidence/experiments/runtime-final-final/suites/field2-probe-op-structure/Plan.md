# Field2 Probe-Op-Structure Runtime Slice — Plan

## Purpose
Provide the runtime plan and bundles that support the probe-op-structure experiment's anchor checks. Structural decoding and inventories remain under `field2-final-final/probe-op-structure`.

## Baseline & scope
- World: `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
- Runtime channel: `launchd_clean` for decision-stage evidence.
- Profiles and SBPL live in the field2 experiment and are referenced by the registry.

## Execution
- Run: `python -m book.api.runtime run --plan book/evidence/experiments/runtime-final-final/suites/field2-probe-op-structure/plan.json --channel launchd_clean --out book/evidence/experiments/runtime-final-final/suites/field2-probe-op-structure/out`
- Emit packet: `python -m book.api.runtime emit-promotion --bundle book/evidence/experiments/runtime-final-final/suites/field2-probe-op-structure/out/LATEST --out book/evidence/experiments/runtime-final-final/evidence/packets/field2-probe-op-structure.promotion_packet.json`
