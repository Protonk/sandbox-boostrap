# Runtime Final Final — Research Report

Status: partial (migration in progress)

## Purpose
Provide a single, host-bound runtime experiment surface for the Sonoma baseline. This root unifies runtime suites, packet-only evidence consumption, and shared runtime guardrails while preserving suite-local plans and artifacts.

## Baseline & scope
- World: `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5` (Sonoma baseline).
- Runtime evidence must be stage- and lane-labeled.
- Apply-stage `EPERM` is almost always evidence of a staging problem, not a policy denial. Run `book/tools/preflight`.
- Non-baseline runtime suites (debug VM or SIP-disabled) are explicitly marked and do not mix with baseline claims.

## Structure (canonical)
- `suites/<suite-name>/` — runtime suites migrated from legacy experiment roots.
- `evidence/packets/` — promotion packets (authoritative runtime boundary).
- `evidence/derived/` — packet-only derived outputs with receipts.
- `registry/suite_index.json` — index of suite plan and packet paths.

## Status
- Migration ongoing: suites are being moved and references updated.
- Legacy experiment roots are being archived as documentation-only stubs.

## Evidence & artifacts
- Promotion packets live under `book/evidence/experiments/runtime-final-final/evidence/packets/`.
- Bundle authority remains each suite's `out/<run_id>/artifact_index.json`.

## Next steps
- Finish suite moves and update all references.
- Refresh derived outputs that embed old packet paths.
- Run `make -C book test` to validate the new structure.
