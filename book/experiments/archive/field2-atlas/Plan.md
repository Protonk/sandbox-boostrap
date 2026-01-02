# Field2 Atlas – Plan (Sonoma baseline)

## Purpose
Build a field2-centric experiment that follows selected field2 IDs end-to-end across the static graph (tag layouts + anchors + canonical system profiles) and a small runtime harness. The goal is to flip the usual anchor/operation view and instead ask: for a given field2 on this host, where does it live in the compiled graphs, which profiles use it, and what happens when we exercise a runtime scenario that should reach it?

## Baseline & scope
- Host world: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5` (fixed).
- Canonical vocab/mappings: `book/graph/mappings/vocab/{ops.json,filters.json}`, `book/graph/mappings/tag_layouts/tag_layouts.json`, `book/graph/mappings/anchors/anchor_filter_map.json`, `book/graph/mappings/system_profiles/{digests.json,static_checks.json}`, `book/experiments/field2-final-final/field2-filters/out/field2_inventory.json`.
- Runtime references: existing traces and signatures under `book/graph/mappings/runtime/` (golden traces, adversarial summary, runtime_signatures.json).
- Initial op focus (runtime-backed on this host): `file-read-data`, `file-write-data`, `mach-lookup`.
- Experiment home: `book/experiments/field2-final-final/field2-atlas/` with outputs in `out/static/` and derived outputs under `out/derived/<run_id>/`.

## Field2 seed set (fixed)
- Seeds are locked in `field2_seeds.json` to keep the slice stable across runs.
- Selection rule for this first cut: field2 IDs that (a) have multiple anchors **or** multiple tag placements in the canonical layouts, (b) appear in at least one canonical system profile, and (c) land on the runtime-backed ops above.
- Current seeds (see manifest for details and sources):
  - `0` (`path`) – anchors `/etc/hosts`, `/tmp/foo`, `IOUSBHostInterface`, `com.apple.cfprefsd.agent`; present in `sys:sample` (tag 7). Primary op: `file-read-data`/`file-write-data`.
  - `5` (`global-name`) – anchors `/etc/hosts`, `/tmp/foo`, `IOUSBHostInterface`, `com.apple.cfprefsd.agent`, `preferences/logging`; present in `sys:bsd` (tag 27). Primary op: `mach-lookup`.
  - `7` (`local`) – anchors `/etc/hosts`, `flow-divert`; present in `sys:sample` (tags 3/7/8). Primary op: `mach-lookup` (runtime-backed via mach/local probes).
  - `4` (`ipc-posix-name`) – present in `sys:bsd` and `sys:airlock`. Primary ops: `ipc-posix-shm*`/`ipc-posix-sem*`.
  - `6` (`local-name`) – probe-backed mach-lookup filter (no system-profile witness in the current inventory).
  - `26` (`right-name`) – present in `sys:bsd` tags; primary op: `authorization-right-obtain`.
  - `27` (`preference-domain`) – present in `sys:bsd` tags; primary ops: `user-preference-read`/`user-preference-write`.
  - `34` (`notification-name`) – present in `sys:airlock` tags; primary ops: `darwin-notification-post`/`distributed-notification-post`.
  - `37` (`sysctl-name`) – vocab-backed seed for sysctl reads (system-profile witness not yet present in the inventory).
  - `49` (`xpc-service-name`) – vocab-backed seed for mach-lookup (system-profile witness not yet present in the inventory).
- Status: seed set remains bounded but now includes a userland-backed tranche; keep additions tight so join surfaces remain inspectable.

## Work plan
1. **Seed curation (locked)**  
   Commit the fixed seed manifest (`field2_seeds.json`) with anchor/profile witnesses and target ops. Add a small helper to re-derive the seed slice from canonical mappings for drift detection (no mutation).
2. **Static join builder**  
   Implement `atlas_static.py` to emit `out/static/field2_records.jsonl` keyed by field2, joining tag IDs (from tag layouts + field2-filters inventory), filter metadata (vocab), anchors (anchor_filter_map + probe-op-structure hits), and system profile counts (field2-filters inventory). Mark coverage as `ok`/`partial` per source status.
3. **Runtime consumption (packet-only)**  
   Consume a promotion packet to resolve runtime exports and emit derived results under `out/derived/<run_id>/runtime/field2_runtime_results.json`, stamped with `(run_id, artifact_index digest)` and a consumption receipt. If no plausible probe, record `runtime_candidate: none`. Treat EPERM/apply gates as `blocked` outcomes, not absence.
4. **Atlas synthesis**  
   Merge static + runtime layers into `out/derived/<run_id>/atlas/field2_atlas.json` and `out/derived/<run_id>/atlas/summary.json`, one row per seed. Compute a coarse status (`runtime_backed`, `static_only`, `no_runtime_candidate`, `blocked`). Keep repo-relative paths to all contributing artifacts and stamp provenance.
5. **Guardrails**  
   Add `book/integration/tests/graph/test_field2_atlas.py` to assert: seed manifest is non-empty, atlas covers every seed, at least one seed is runtime-attempted, and derived outputs are provenance-stamped from a promotion packet.
6. **Reporting**  
   Keep `Report.md` aligned with actual outputs; record failed probes or gaps in `Notes.md`.

## Status (initial)
- Seed manifest drafted; scaffolding for static/runtime/atlas layers to be filled in. No new runtime execution yet; current runtime entries reference existing golden traces as placeholders until the dedicated harness runs.
