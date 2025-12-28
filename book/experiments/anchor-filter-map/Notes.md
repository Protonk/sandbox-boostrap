# Anchor ↔ Filter ID Mapping – Notes

Use this file for concise notes on progress, commands, and intermediate findings.

## First pass

- Experiment scaffolded (plan/report/notes). Goal: convert anchor hits into a filter-ID map, landing at `book/graph/mappings/anchors/anchor_filter_map.json`. No data pass yet.

## Second pass

- Baseline data pass: loaded `probe-op-structure/out/anchor_hits.json` and harvested anchors with field2 hints; wrote initial candidates to `out/anchor_filter_candidates.json` (anchor → {field2_names, field2_values, sources}). Field2 inventory not yet merged; next step is disambiguation and mapping to filter IDs.
- Migrated anchor mapping semantics to a ctx-indexed canonical surface: `book/graph/mappings/anchors/anchor_ctx_filter_map.json` is the source of truth, and `book/graph/mappings/anchors/anchor_filter_map.json` is a conservative, derived compatibility view that remains blocked whenever a literal participates in multiple contexts.
- Updated `flow-divert` anchor entry with `filter_name: local`, retained candidates, and added characterization note from flow-divert-2560 matrix (triple-only domain+type+proto, tag0/u16_role=filter_vocab_id, literal `com.apple.flow-divert`); status still `blocked`.

## Runtime discriminator (mach-lookup predicate kind) – `com.apple.cfprefsd.agent`

Goal: produce a clean, promotable runtime discriminator matrix that distinguishes `global-name` vs `local-name` for `mach-lookup` on this host, and tie the result to the **canonical ctx entry** rather than treating the literal string as a unique binding.

Run provenance:
- `run_id`: `028d4d91-1c9e-4c2f-95da-7fc89ec3635a` (launchd clean channel)
- Promotion packet: `book/experiments/anchor-filter-map/out/promotion_packet.json`
- Promotion receipt: `book/graph/mappings/runtime/promotion_receipt.json` (packet `status: used`)

Commands:
- `python -m book.api.runtime_tools run --plan book/experiments/anchor-filter-map/plan.json --channel launchd_clean --out book/experiments/anchor-filter-map/out`
- `python -m book.api.runtime_tools emit-promotion --bundle book/experiments/anchor-filter-map/out --out book/experiments/anchor-filter-map/out/promotion_packet.json --require-promotable`
- `PYTHONPATH=$PWD python book/graph/mappings/runtime/promote_from_packets.py --packet-set book/graph/mappings/runtime/packet_set.json`
- `python book/graph/mappings/anchors/generate_anchor_filter_map.py`
- `make -C book test`

Outcome summary (bounded; host-scoped):
- Baseline lane shows the service is **observable** (`kr=0`) and a bogus name is **unregistered** (`kr=1102`).
- Under `(deny default)`, S0 (allow `mach-lookup` unfiltered) allows; N1 (no allow for the target) denies (`kr=1100`).
- Predicate discrimination under `(deny default)`: allowing `global-name` allows; allowing `local-name` denies (`kr=1100`); allowing both allows.
- Mapping-fidelity controls under `(allow default)`: denying `global-name` denies; denying `local-name` does not.
- Canonical ctx map contains a `com.apple.cfprefsd.agent@global-name` ctx entry; the legacy literal-keyed view remains blocked (multiple contexts exist for the same literal).

## Runtime discriminator (iokit-open-service class) – `IOUSBHostInterface`

Goal: attempt to lift the `IOUSBHostInterface` anchor out of `status: blocked` in `book/graph/mappings/anchors/anchor_filter_map.json` by producing a clean, promotable runtime discriminator matrix for `iokit-open-service` predicate kind.

Run provenance:
- `run_id`: `bf80e47b-3020-4b13-bfa7-249cfcff8b52` (launchd clean channel)
- Promotion packet: `book/experiments/anchor-filter-map/iokit-class/out/promotion_packet.json`
- Promotion receipt: `book/graph/mappings/runtime/promotion_receipt.json` (packet `status: used`)

Commands:
- `python -m book.api.runtime_tools run --plan book/experiments/anchor-filter-map/iokit-class/plan.json --channel launchd_clean --out book/experiments/anchor-filter-map/iokit-class/out`
- `python -m book.api.runtime_tools emit-promotion --bundle book/experiments/anchor-filter-map/iokit-class/out --out book/experiments/anchor-filter-map/iokit-class/out/promotion_packet.json --require-promotable`
- `PYTHONPATH=$PWD python book/graph/mappings/runtime/promote_from_packets.py --packet-set book/graph/mappings/runtime/packet_set.json`
- `python book/graph/mappings/anchors/generate_anchor_filter_map.py`

Outcome summary (bounded; host-scoped):
- Baseline lane reports `found=false` for `IOUSBHostInterface` in this process context (unobservable), so the anchor remains `status: blocked`.
- The promotable packet/receipt captures the attempted discriminator run, but it does not provide evidence about which filter family is consulted when the acquisition path cannot be reached.
