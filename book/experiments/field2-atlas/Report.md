# Field2 Atlas — Research Report — **Status: partial**

## Purpose
Follow specific field2 IDs (0 `path`, 5 `global-name`, 7 `local`) end-to-end across tag layouts, anchors, canonical system profiles, and a tiny runtime harness. Field2 is the primary key: we start from a field2 ID and ask where it shows up and what happens at runtime when we poke it.

## Position in the book
This is the canonical example of a field2-first view. It is intentionally narrow (0/5/7 + one static-only neighbor) and wires directly into existing mappings and runtime traces rather than trying to cover all field2 values.

## Setup
- World: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
- Seed set: fixed in `field2_seeds.json` (0/5/7 with anchors + profile witnesses, 1 as nearby static neighbor, 2560 as characterized flow-divert triple-only token: tag0/u16_role=filter_vocab_id/literal `com.apple.flow-divert`).
- Inputs: `book/graph/mappings/vocab/{ops.json,filters.json}`, `book/graph/mappings/tag_layouts/tag_layouts.json`, `book/graph/mappings/anchors/anchor_filter_map.json`, `book/graph/mappings/system_profiles/{digests.json,static_checks.json}`, `book/experiments/field2-filters/out/field2_inventory.json`, runtime signatures/traces under `book/graph/mappings/runtime/` (notably `runtime_signatures.json`). Runtime events/baseline/manifests are sourced from the runtime-adversarial promotion packet; legacy out/ paths require `--allow-legacy`.
- Deliverables: static records (`out/static/field2_records.jsonl`), runtime results (`out/runtime/field2_runtime_results.json`), and merged atlas (`out/atlas/field2_atlas.json`, `out/atlas/summary.json`).

## Outputs (current)
- `out/static/field2_records.jsonl` — one record per seed with tag IDs, anchors, and system-profile placements for that field2; all seeds present by construction.
- `out/runtime/field2_runtime_results.json` — one entry per seed, each tagged to a concrete runtime scenario (profile, operation, expected/result, scenario_id). Seeds without a candidate are marked `no_runtime_candidate`.
- `out/atlas/field2_atlas.json` — static + runtime merged per field2 with a coarse status (`runtime_backed`, `runtime_backed_historical`, `runtime_attempted_blocked`, `static_only`, `no_runtime_candidate`).
- `out/atlas/summary.json` — counts by status to show field2 coverage at a glance.

## Status
- Static: `ok` for the seed slice including seed `2560` (characterized flow-divert triple token).
- Runtime: **partial** — refreshed via the launchd clean channel; decision-stage results are current but structural/path mismatches remain (notably `adv:path_edges:allow-subpath` for field2=1), so runtime mappings remain `partial`.
- Atlas: rebuilt after the refreshed runtime signatures and static inventory; field2=1 is now runtime-attempted with a bounded mismatch packet, and field2=2560 is runtime-backed with a control witness.

## Case studies (seed slice)
- Field2 0 (`path`): Appears on path-centric tags in `sys:sample` and multiple probes; anchors include `/etc/hosts` and `/tmp/foo`. Runtime scenario `field2-0-path_edges` targets path edges (file-read*). The canonicalization boundary is explicit: the runtime record carries `requested_path=/tmp/...`, `normalized_path=/private/tmp/...`, and a `path_canonicalization_witness` sourced from the `adv:path_alias` twin-probe profile.
- Field2 5 (`global-name`): Present in `sys:bsd` tag 27 and many mach/path probes; anchors include `preferences/logging` and `/etc/hosts`. Runtime scenario `field2-5-mach-global` (mach-lookup `com.apple.cfprefsd.agent`) is decision-stage current.
- Field2 7 (`local`): Present in `sys:sample` tags 3/7/8 and network/mach probes; anchors include `/etc/hosts` and blocked `flow-divert`. Runtime scenario `field2-7-mach-local` is decision-stage current.
- Field2 1 (`mount-relative-path`): Anchored via `/etc/hosts` and present in `sys:sample` tag 8; runtime scenario `adv:path_edges:allow-subpath` is deny where expected allow. The mismatch is captured as a packet in `book/experiments/runtime-adversarial/out/mismatch_packets.jsonl` with baseline/oracle/normalization controls and labeled `path_normalization_sensitivity`.
- Field2 2560 (`flow-divert triple`): Characterized static token for combined domain/type/proto in flow-divert probes; tag0/u16_role=filter_vocab_id with literal `com.apple.flow-divert`, target op `network-outbound`. Runtime scenario `adv:flow_divert_require_all_tcp` now yields a decision-stage allow and is paired with a partial-triple control (`adv:flow_divert_partial_tcp`) plus a baseline connect check; the control is currently non-discriminating and is labeled as such in `out/runtime/field2_runtime_results.json`.

## Evidence & artifacts
- Seeds: `book/experiments/field2-atlas/field2_seeds.json`
- Static: `book/experiments/field2-atlas/out/static/field2_records.jsonl`
- Runtime: `book/experiments/field2-atlas/out/runtime/field2_runtime_results.json`
- Atlas: `book/experiments/field2-atlas/out/atlas/{field2_atlas.json,summary.json}`
- Helpers: `atlas_static.py`, `atlas_runtime.py`, `atlas_build.py`; guardrail `book/tests/planes/graph/test_field2_atlas.py`.
- Mismatch packets: `book/experiments/runtime-adversarial/out/mismatch_packets.jsonl` (decision-stage mismatch bundles).
- Promotion packet: `book/experiments/runtime-adversarial/out/promotion_packet.json` (required for runtime events + baseline results + run manifest unless `--allow-legacy` is passed).

## Next steps
- If the path-edge mismatch remains after normalization controls, tighten the expectation or anchor join for field2=1 and keep the mismatch packet updated with an explicit reason.
- Try a discriminating flow-divert control (alter domain/type/proto filter shape) so field2=2560 has a positive/negative contrast rather than an allow-only witness.
- Keep the runtime corpus current via the standard harness + validation pipeline, then refresh `atlas_runtime.py` and `atlas_build.py`.
