# Runtime Final Final — Plan

## Purpose
Consolidate all runtime-facing experiments into a single, host-scoped experiment surface for the Sonoma baseline. This root is the canonical home for runtime harness plans, bundles, promotion packets, and packet-only derived outputs.

## Baseline & scope
- World: `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5` (unless explicitly marked non-baseline).
- Scope: runtime bundles (`artifact_index.json`), promotion packets, and packet-only consumers.
- Non-baseline runtime suites (debug VMs or SIP-disabled worlds) live under `suites/nonbaseline/` and must carry their own world metadata.

## Structure (canonical)
- `suites/<suite-name>/` — one suite per legacy experiment.
  - Must include: `Plan.md`, `Report.md`, `Notes.md`, and `out/` (bundles).
  - Include `plan.json` + `registry/` when the suite uses plan-based runtime runs.
  - Include `sb/` when the suite owns SBPL sources.
- `evidence/packets/` — promotion packets for suites (packet-only consumption boundary).
- `evidence/derived/` — packet-only derived outputs (with consumption receipts).
- `evidence/receipts/` — mapping deltas or promotion receipts (packet provenance).
- `scripts/` — shared runtime helpers (thin wrappers only; suite scripts stay in-suite).
- `registry/suite_index.json` — world-bound suite index (plan path + packet path(s) + status).

## Invariants
- Runtime evidence is only promotable from committed bundles or promotion packets.
- Apply-stage `EPERM` remains hypothesis evidence; do not treat it as policy semantics.
- All runtime statements are stage- and lane-labeled (`compile|apply|bootstrap|operation`, `scenario|baseline|oracle`).
- Packets are the authority boundary for derived outputs; no direct `out/LATEST` scraping in consumers.

## Execution paths
- Canonical runtime run:
  - `python -m book.api.runtime run --plan <suite>/plan.json --channel launchd_clean --out <suite>/out`
- Packet emission:
  - `python -m book.api.runtime emit-promotion --bundle <suite>/out/LATEST --out book/evidence/experiments/runtime-final-final/evidence/packets/<suite>.promotion_packet.json`
- Derived outputs:
  - Each suite-level derived script must accept a `--packet` path and emit a `consumption_receipt.json` under `evidence/derived/`.

## Migration checklist (for each suite)
- Move suite under `suites/<suite-name>/` with its full scaffold.
- Update any absolute or old experiment paths in docs and scripts.
- Update consumers to use `evidence/packets/` paths (packet-only).
- Archive the old experiment root (docs only).

## Guardrails
- Only supported repo-wide test entrypoint: `make -C book test`.
- Do not hand-edit generated artifacts (mappings, validation IR, CARTON).
