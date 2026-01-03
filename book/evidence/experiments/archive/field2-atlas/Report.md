# Field2 Atlas — Research Report — **Status: partial**

## Purpose
Follow a fixed seed slice of field2 IDs (0 `path`, 1 `mount-relative-path`, 2 `xattr`, 3 `file-mode`, 4 `ipc-posix-name`, 5 `global-name`, 6 `local-name`, 7 `local`, 26 `right-name`, 27 `preference-domain`, 34 `notification-name`, 37 `sysctl-name`, 49 `xpc-service-name`, 2560 flow-divert triple) end-to-end across tag layouts, anchors, canonical system profiles, and the runtime harness. Field2 is the primary key: we start from a field2 ID and ask where it shows up and what happens at runtime when we poke it.

## Position in the book
This is the canonical example of a field2-first view. It is intentionally narrow (a curated seed slice that stays tied to concrete witnesses) and wires directly into existing mappings and runtime traces rather than trying to cover all field2 values.

## Setup
- World: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
- Seed set: fixed in `field2_seeds.json` (baseline slice plus a userland-backed tranche: `ipc-posix-name`, `local-name`, `right-name`, `preference-domain`, `notification-name`, `sysctl-name`, `xpc-service-name`). Some of these seeds are system-profile-backed (bsd/airlock), while others currently rely on vocab-only IDs and probe profiles until a runtime witness is added.
- Inputs: `book/integration/carton/bundle/relationships/mappings/vocab/{ops.json,filters.json}`, `book/integration/carton/bundle/relationships/mappings/tag_layouts/tag_layouts.json`, `book/integration/carton/bundle/relationships/mappings/anchors/anchor_filter_map.json`, `book/integration/carton/bundle/relationships/mappings/system_profiles/{digests.json,static_checks.json}`, `book/evidence/experiments/field2-final-final/field2-filters/out/field2_inventory.json`, runtime signatures under `book/integration/carton/bundle/relationships/mappings/runtime/` (notably `runtime_signatures.json`). Runtime events/baseline/manifest are resolved from the promotion packet export surface.
- Deliverables: static records (`out/static/field2_records.jsonl`) plus derived runtime + atlas outputs under `out/derived/<run_id>/` with a stamped `consumption_receipt.json`.

## Outputs (derived)
- `out/static/field2_records.jsonl` — one record per seed with tag IDs, anchors, and system-profile placements for that field2; all seeds present by construction.
- `out/derived/<run_id>/runtime/field2_runtime_results.json` — one entry per seed, each tagged to a concrete runtime scenario (profile, operation, expected/result, scenario_id). Seeds without a candidate are marked `no_runtime_candidate`.
- `out/derived/<run_id>/atlas/field2_atlas.json` — static + runtime merged per field2 with a coarse status (`runtime_backed`, `runtime_backed_historical`, `runtime_attempted_blocked`, `static_only`, `no_runtime_candidate`).
- `out/derived/<run_id>/atlas/summary.json` — counts by status to show field2 coverage at a glance.
- `out/derived/<run_id>/consumption_receipt.json` — packet path, upstream run_id + artifact_index digest, and derived outputs written.
- `out/derived/<run_id>/atlas/mapping_delta.json` — proposal set for upgrading weak runtime candidates using packet-resolved events.

## Status
- Static: **partial** for the expanded tranche — `ipc-posix-name`, `right-name`, `preference-domain`, and `notification-name` have system-profile placements, while `sysctl-name` and `xpc-service-name` rely on seed-manifest anchors until a static witness is observed in the inventory.
- Runtime: **partial** — refreshed via the launchd clean channel; path_edges mismatches persist as canonicalization boundaries in the adversarial suite, while field2 0 uses the `/private/tmp` control profile (`adv:path_edges_private`) and field2 1 uses the dedicated mount-relative-path discriminator (`adv:mount_relative_path`) so both runtime candidates reach operation stage. New runtime candidates are added for `local-name`, `notification-name`, and `sysctl-name` via existing mach/hardened signatures.
- Mapping delta: runtime signatures were refreshed from the promotion packet, and the atlas reflects the updated candidates.
- Atlas: rebuilt after the refreshed runtime signatures and static inventory; field2=2 (xattr) and field2=3 (file-mode) are now runtime-backed, and field2=2560 remains runtime-backed with the flow-divert control witness.
- Current posture: the original seed slice remains runtime-backed, while the new tranche requires sandbox_check or hardened-runtime evidence to move beyond static-only coverage.

## Case studies (seed slice)
- Field2 0 (`path`): Appears on path-centric tags in `sys:sample` and multiple probes; anchors include `/etc/hosts` and `/tmp/foo`. Runtime scenario `adv:path_edges_private:allow-tmp` targets `/tmp/...` with normalization to `/private/tmp/...`, and the decision is allow at operation stage. The canonicalization boundary is explicit via `requested_path`/`normalized_path` plus the `adv:path_alias` twin-probe witness.
- Field2 5 (`global-name`): Present in `sys:bsd` tag 27 and many mach/path probes; anchors include `preferences/logging` and `/etc/hosts`. Runtime scenario `field2-5-mach-global` (mach-lookup `com.apple.cfprefsd.agent`) is decision-stage current.
- Field2 7 (`local`): Present in `sys:sample` tags 3/7/8 and network/mach probes; anchors include `/etc/hosts` and blocked `flow-divert`. Runtime scenario `field2-7-mach-local` is decision-stage current.
- Field2 1 (`mount-relative-path`): Anchored via `/etc/hosts` and present in `sys:sample` tag 8; runtime scenario `adv:mount_relative_path:allow-subpath` reaches operation stage and allows, paired with `adv:mount_relative_path:deny-outside` as the negative control, so the mount-relative-path discriminator is now clean of `/tmp` alias confounds.
- Field2 2 (`xattr`): Present in `sys:bsd` tag 26 and field2 inventory; runtime scenario `adv:xattr:allow-foo-read` reaches operation stage and allows on `/private/tmp/foo`, providing the current runtime-backed witness for `file-read-xattr`.
- Field2 3 (`file-mode`): Present in `sys:bsd` tag 27 and `sys:sample` tags 3/8; runtime scenario `adv:file_mode:allow-private` reads `/private/tmp/mode_deny` (0600) successfully, while `adv:file_mode:deny-world` denies `/private/tmp/mode_allow` (0644), providing the current file-mode witness.
- Field2 2560 (`flow-divert triple`): Characterized static token for combined domain/type/proto in flow-divert probes; tag0/u16_role=filter_vocab_id with literal `com.apple.flow-divert`, target op `network-outbound`. Runtime scenario `adv:flow_divert_require_all_tcp` now yields a decision-stage allow with a baseline listener control; the partial-triple control (`adv:flow_divert_partial_tcp`) also allows, so it remains non-discriminating but no longer ambient-restricted.

## Evidence & artifacts
- Seeds: `book/evidence/experiments/field2-final-final/field2-atlas/field2_seeds.json`
- Static: `book/evidence/experiments/field2-final-final/field2-atlas/out/static/field2_records.jsonl`
- Runtime (derived): `book/evidence/experiments/field2-final-final/field2-atlas/out/derived/<run_id>/runtime/field2_runtime_results.json`
- Atlas (derived): `book/evidence/experiments/field2-final-final/field2-atlas/out/derived/<run_id>/atlas/{field2_atlas.json,summary.json}`
- Delta (derived): `book/evidence/experiments/field2-final-final/field2-atlas/out/derived/<run_id>/atlas/mapping_delta.json`
- Receipt: `book/evidence/experiments/field2-final-final/field2-atlas/out/derived/<run_id>/consumption_receipt.json`
- Helpers: `atlas_static.py`, `atlas_runtime.py`, `atlas_build.py`; guardrail `book/integration/tests/graph/test_field2_atlas.py`.
- Promotion packet: promotion packet path (required for runtime exports and provenance).

## Next steps
- If the path-edge mismatch remains after normalization controls, keep the mismatch packet updated with the explicit canonicalization-boundary reason.
- Try a discriminating flow-divert control (alter domain/type/proto filter shape) so field2=2560 has a positive/negative contrast rather than an allow-only witness.
- Keep the runtime corpus current via the standard harness + validation pipeline, then refresh `atlas_runtime.py` and `atlas_build.py`.
