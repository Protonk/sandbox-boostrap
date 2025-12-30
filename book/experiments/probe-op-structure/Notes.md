# Probe Op Structure – Notes

Use this file for concise notes on probe designs, compile logs, and findings.

## Initial scaffold and goals

- Experiment initialized. Vocab artifacts available (ops: 196, filters: 93). Pending: define probe matrix that mixes multiple filters/ops and deeper metafilters to tease out filter-specific `field2` values beyond generic path/name nodes.
- Added initial probe matrix and SBPL variants:
  - Single-op file variants: `v0_file_require_all`, `v1_file_require_any`, `v2_file_three_filters_any`.
  - Single-op mach/network/iokit: `v3_mach_global_local`, `v4_network_socket_require_all`, `v5_iokit_class_property`.
  - Mixed variants: `v6_file_mach_combo`, `v7_file_network_combo`, `v8_all_combo`.
- Compiled via `libsandbox`; decoded with vocab padding. Early observations from `out/summary.json`:
  - Field2 remains dominated by low IDs: `global-name` (5), `local-name` (6), `ipc-posix-name` (4), `file-mode` (3), `remote` (8). Even filter-diverse profiles surface these generic IDs.
  - Network profile (`v4`) shows `remote` (8) from graph walk; file/network combo (`v7`) shows `remote` for both ops.
  - Mach/global/local variants show {5,6}; file-only require-all/any variants show {3,4} or {5,6} depending on decoder op_count.
  - Decoder heuristic failed on `v8_all_combo` (node_count 0, all ops bucket 0) likely due to literal-start detection; needs better slicing if we revisit.
- Revised plan (do not implement yet): shift to anchor-based traversal and improved slicing:
  - Add segment-aware slicing fallback to avoid node_count=0 on complex profiles.
  - Use literal anchors (unique paths, mach names, iokit classes) to locate filter-specific nodes and read their `field2`.
  - Design profiles with disjoint anchors per filter family and multi-op separation to reduce path/name masking.
  - Cross-check with system profiles and add guardrails once mappings stabilize.
- Ran `analyze_profiles.py` to gather field2 histograms and literal samples for probes and system profiles (`out/analysis.json`):
  - Probes still dominated by low/generic IDs: file probes heavy on `ipc-posix-name`/`file-mode`; mach/iokit variants show {5,6}; network shows {8,7} plus occasional `xattr`/unknown 2560.
  - System profiles reaffirm higher-ID filters (`bsd`: 27=`preference-domain`, 26=`right-name`, etc.; `sample`: low path/socket IDs; `airlock`: high unknowns 166/165/10752).
  - Literal samples confirm anchors present (e.g., `/tmp/foo`, `/etc/hosts`, mach service, iokit class), but decoder traversal still does not reach filter-specific nodes; masking persists.
- Added `anchor_map.json` (anchor strings per profile) and `anchor_scan.py` to search for anchors → node indices → `field2`. Current results (`out/anchor_hits.json`):
  - Anchors are found in literal strings (e.g., `/tmp/foo`, `/etc/hosts`, mach name, iokit class), but `node_indices` remain empty across probes/system profiles—decoder node fields aren’t directly pointing to anchor offsets with current slicing.
  - Confirms we need better node/literal association (segment-aware slicing or richer node decoding) to bridge anchors to nodes and `field2`.
- Implemented a minimal Mach-O segment parser in `profile_ingestion.py` to improve slicing; reran `analyze_profiles.py` with the fallback. `v8_all_combo` now slices nodes (nodes_len=424) but anchor_scan still fails to link anchors to nodes (empty `node_indices`), indicating node→literal references are not captured by the current decoder fields.
- Brute inspection of `v1_file_require_any`:
  - Anchors reside in the literal pool as prefixed strings (`Ftmp/foo`, `Hetc/hosts`) at offsets ~461/477.
  - Node fields (stride-12 heuristic) only contain small values {0,1,2,3,5,6}; no values near literal offsets, so anchors do not show up in decoded node fields.
  - Conclusion: the current heuristic node parsing exposes filter IDs but not literal offsets; node↔literal association will require a richer decode of modern node records beyond the simple 12-byte/field view.
- Updated `anchor_scan.py` to use raw section slicing and search node bytes for anchor offsets (relative/absolute) with strides 12/16. Anchors in literal pools are located (e.g., `/tmp/foo` at offset ~43 within pool), but no node bytes contain these offsets; `node_indices` remain empty. Fields still only carry small filter-ID-like values, confirming we need a deeper node decoder to expose literal references.
- Added `map_literal_refs.py` to brute-force scan node bytes for literal offsets; outputs `out/literal_scan.json`. Across probes, literal offsets are found in the pools (e.g., mach name at offset 54, flow-divert at 59), but no hits in node word scans (16-bit words). This reinforces that literal references are not present in the exposed node words; a richer node decoding is required to find literal bindings.
- Added an initial `node_decoder.py` (tag-aware scaffold) and wired it into `map_literal_refs.py` for tag counts; no anchor hits yet. Node operands remain small and do not match literal offsets, even after tag-aware parsing, underscoring the need for a fuller modern node format decode.
- Dumped raw node bytes grouped by tag for several profiles (`out/tag_bytes.json`). Observations:
  - Probes use low tag IDs (0–8, 11–13) with highly repetitive u16 patterns; no obvious literal offsets.
  - `bsd` profile shows higher tags (17,26,27) and tag0 chunks containing `0e01`-like sequences; still no direct literal matches, but suggests richer tag set in system profiles.
  - No anchor offsets appear in node bytes even with expanded tag sampling, reinforcing that literal references are encoded differently (likely outside the visible 16-bit operand slots).

## IOSurface anchor addition

- Added `v9_iokit_user_client_only.sb` with `(allow iokit-open-user-client (iokit-user-client-class "IOSurfaceRootUserClient"))` and compiled to `sb/build/v9_iokit_user_client_only.sb.bin`.
- Updated `anchor_map.json` to include `IOSurfaceRootUserClient`; reran `analyze_profiles.py`, `anchor_scan.py`, `map_literal_refs.py`, `tag_inventory.py`, and `tag_layout_hypotheses.py`.
- `anchor_hits.json` now reports IOSurfaceRootUserClient anchor hits (node indices 46/47/48/50) with field2 values {0,1}; `anchor_field2_map.json` and `anchor_ctx_filter_map.json` were regenerated, yielding a blocked literal entry in `anchor_filter_map.json` due to mixed contexts (filter_id 1 + arg_u16).

## IOSurface anchor pair probe

- Added `v10_iokit_user_client_pair.sb` with two allow rules for `IOSurfaceRootUserClient` and `IOHIDParamUserClient`; compiled to `sb/build/v10_iokit_user_client_pair.sb.bin`.
- Updated `anchor_map.json` to include both anchors and reran `analyze_profiles.py`, `anchor_scan.py`, `map_literal_refs.py`, `tag_inventory.py`, and `tag_layout_hypotheses.py`.
- Observed SBPL literal pool compression that drops the leading `IO` prefix (literal strings like `SurfaceRootUserClient`); updated `anchor_scan.py` to treat `IO*` anchors as matches when the stripped literal matches the anchor minus the `IO` prefix.
- `anchor_hits.json` now reports IOSurfaceRootUserClient and IOHIDParamUserClient node hits in `probe:v10_iokit_user_client_pair`, with IOSurfaceRootUserClient carrying field2 values {0,1,4} and IOHIDParamUserClient carrying {0,1,4,18753}; anchor maps regenerated to include these observations as structural hints.

## IOSurface connection co-anchor probe

- Added `v11_iokit_user_client_connection.sb` with `(require-all (iokit-user-client-class "IOSurfaceRootUserClient") (iokit-connection "IOAccelerator"))`; compiled to `sb/build/v11_iokit_user_client_connection.sb.bin`.
- Updated `anchor_map.json` and reran the structural pipeline (`analyze_profiles.py`, `anchor_scan.py`, `map_literal_refs.py`, `tag_inventory.py`, `tag_layout_hypotheses.py`).
- `anchor_hits.json` now reports IOSurfaceRootUserClient with field2 values {0,5} (tag 0 `global-name` plus tag 6 `arg_u16` carrying 0/5) and IOAccelerator with {0,1,5}; both remain structurally blocked due to mixed contexts, but the co-anchor adds a distinct `global-name` context for IOSurface that was not visible in v9/v10.

## Delta attribution for IOSurfaceRootUserClient

- Added control profile `v12_iokit_control.sb` (deny default only) and compiled to `sb/build/v12_iokit_control.sb.bin`.
- Added `delta_attribution.py` to compare the v12 control blob against the v9 IOSurface variant and emit `out/anchor_hits_delta.json` with only `u16_role == filter_vocab_id` nodes. The delta run excludes the generic `path` filter context for IOSurface (filter_id 0).
- `generate_anchor_field2_map.py` now prefers delta hits for IOSurfaceRootUserClient, yielding a single `mount-relative-path` structural binding in `anchor_ctx_filter_map.json` and an unblocked literal entry in `anchor_filter_map.json`.
- Additional structure poking:
  - Node region lengths vary and are not always multiples of 12; `bsd` nodes_len=498 (mod4=2), suggesting non-12-byte layouts.
  - Tag sets depend on stride: e.g., `bsd` shows tags {0,1,5,11,15,17,18,20,26,27} at stride=6, shrinking to {0,17,26,27} at stride=12; layout likely differs per tag/stride.
  - First bytes of `bsd` node region: repeated patterns (`1b001b00130012...`) hint at larger operand widths; underscores that fixed-stride parsing is inadequate.
- Further poking (node region patterns):
  - Counting u32 words shows dominant repeated values (`0x1b001b`, `0x1b001a`, `0x1a001a`), suggesting paired 16-bit operands packed together.
  - Stride-based tag extraction shows many tag IDs at smaller strides (6/10) that collapse at stride 12; node sizes likely vary by tag.
  - Heuristic payload extraction (tag,u16,u16,u32) yields repeating payloads for bsd; still no literal offsets.
  - Overall: evidence points to variable-layout nodes with 16-bit edge-like fields and 32-bit payloads; literal refs are not visible without per-tag layouts.
- Updated anchor_scan to guess anchor string index within literal pool (printable runs). We now map anchors to literal_string_index but still see no node_indices/field2: nodes remain unlinked. Literal pools contain anchors with indices (e.g., flow-divert index 0), but decoded node operands don’t match these indices.
- Planning next steps (anchor-based slicing/traversal):
  - Implement segment-aware slicing fallback (Mach-O offsets for node/literal boundaries) to avoid node_count=0 cases like `v8_all_combo`; record when fallback is used.
  - Enforce anchor uniqueness per filter family; generate anchor maps per profile.
  - Traverse by anchor: find nodes referencing anchors and record `field2`/tags/op-table context, using op-entry walks only as secondary context.
  - Cross-check anchor hits against system profiles; note mismatches.
  - Persist all intermediate JSON (segment offsets, slices, anchor hits, field2 findings) and dated notes; keep mappings versioned to host/build.
  - Once mappings emerge, produce a small artifact (filter ID/name ↔ observed field2 with provenance) and a guardrail checker that asserts expected `field2` for given anchors.

## First probe matrix

- Updated `anchor_scan.py` to include an `offsets` field (alias of `literal_offsets`) in each anchor entry to satisfy anchor output tests. Regenerated `out/anchor_hits.json`.
- Planning the decoder push:
  - Add a per-tag inventory pass: collect bytes/stride candidates per tag across probes/system profiles to separate “front” vs “tail” sanity before decoding layouts.
  - Form tag-specific layout hypotheses and evaluate via edge in-bounds rates and literal/regex operand plausibility (using literal-only deltas and system-profile anchors).
  - Use literal content/count deltas (foo→bar, N literals) to spot which tag/field positions move with literals; treat stride scans only as slicing sanity checks.

## Decoder and slicing updates

- Added `tag_inventory.py` to generate coarse stride-based tag counts/remainders across probe and system profiles (strides 6/8/10/12/16). Output: `out/tag_inventory.json`. This is purely a slicing sanity check; next step is per-tag layout hypotheses using these counts as guardrails.
- Quick spot checks from `tag_inventory.json`:
  - `sys:bsd` tag sets collapse from many tags at stride 6 ({0,1,5,11,15,17,18,20,26,27,80,109,115,170,174}) to {0,17,26,27} at stride 12/16 (rem 6/2), reinforcing tag-dependent sizes.
  - `sys:airlock` shows high tags (165/166/194) at smaller strides; stride 12 still leaves rem 11 with tags {0,1,10,166,74}.
  - `probe:v1_file_require_any` toggles tags between {0,1,3,5,6} (stride 6) and {0,1,5,6} (stride 12), confirming stride choice changes visible tags.
- Added `tag_layout_hypotheses.py` to probe tags {0,5,6,17,26,27} at strides 12/16 with simple edge-in-bounds and field2 histograms. Output: `out/tag_layout_hypotheses.json`.
  - Probes: tags 5/6 have all edges in-bounds at stride 12 (and stride 16), counts shrink at stride 16; field2 for tag6 skews to {5,6} with a single 0/3 in some cases.
  - System `bsd`: stride 12 yields more tag26 records (18) with partial in-bounds edges (30/36) vs stride16 (5 records, 10/10 edges); tag27 edges fully in-bounds both strides. Stride ambiguity remains; need per-tag layouts beyond fixed-stride.
  - This is an exploratory sanity check; pausing before trying broader tag/stride combinations to avoid combinatorial blowup.
- Recorded initial tag layout assumptions in `out/tag_layout_assumptions.json`:
  - Hypothesis: tags 5 and 6 use 12-byte records with fields[0:2] edges and fields[2] as the field2 key (edges in-bounds across probes). Literal/regex mapping still pending.
  - Tags 26/27 left pending; stride-12 vs stride-16 ambiguity noted for system profiles.
- Decoder update (non-layout): added validation metadata (node remainders, edge in-bounds counts, section offsets) to decoder output to aid sanity checks; tests updated to cover presence of validation fields.

## Anchor-aware probes

- Updated `decoder.py` to load tag-layout hints from `out/tag_layout_assumptions.json`, parse nodes with per-tag record sizes, and surface extra section offsets. This keeps the existing stride-12 view but tags nodes with `record_size` and merges external layouts for validation.
- Reran `anchor_scan.py` with the new decoder; `anchor_hits.json` refreshed. Anchors are still found in literal pools but no node indices resolve yet (literal bindings remain hidden), confirming the need for deeper node decoding to expose literal/regex operands.

## Segment-aware slicing

- Decoder now emits `literal_strings_with_offsets` plus per-node `literal_refs` (heuristic: fields matching literal offsets/absolute offsets). Fixed a bug in the matching (previous tuple truthiness made every node look bound).
- `anchor_scan.py` now normalizes prefixed literals (e.g., `Ftmp/foo`) when matching anchors and prefers decoded `literal_refs`, falling back to byte scans only if no ref hits. Anchors now resolve to literal offsets even when prefixed, though node indices remain empty for the current probes.
- Added tests to cover decoder literal offsets/refs and anchor offset discovery.

## Anchor scan and tag inventory

- Extended decoder literal matching: `literal_refs` now also scan node chunks for u16/u32 patterns of literal offsets, absolute offsets, and literal indices. This surfaced node hits for anchors in simple probes (e.g., `/tmp/foo` in `v1_file_require_any` now maps to nodes [16,22,30]).
- Updated `anchor_scan` to prefer decoded `literal_refs` (with normalized prefixes) over raw byte scans; anchor hits now include node indices where available.
- Strengthened `book/tests/planes/graph/test_anchor_scan.py` to assert node_indices are populated for the anchored probe blob.

## Decoder wiring and refresh

- Adjusted `analyze_profiles.py` and `anchor_scan.py` to compute the repository root as three parents up from this experiment directory (so `book.*` imports resolve correctly), then reran both scripts from the repo root. `out/analysis.json` and `out/anchor_hits.json` are now refreshed under the current `book.api.profile.decoder` (which prefers `book/graph/mappings/tag_layouts/tag_layouts.json` when present).

## Refresh with updated layouts/contracts

- Reran `analyze_profiles.py` and `anchor_scan.py` after landing the header/tail contracts and new tag layouts (meta tags 2/3, payload tag10). Outputs are aligned with the trimmed node region and current decoder; anchor hits for flow-divert/bsd/airlock/system profiles remain structurally stable.

## Runtime slice (plan-based)

- Added a minimal runtime plan + registry (`plan.json`, `registry/{profiles,probes}.json`) and registered the new runtime registry in `book/api/runtime/plans/registry/index.json`.
- Preflight scan (`python3 book/tools/preflight/preflight.py scan ...`) reports `no_known_apply_gate_signature` for `v1_file_require_any`, `v3_mach_global_local`, and `v5_iokit_class_property`.
- Ran `python -m book.api.runtime run --plan book/experiments/probe-op-structure/plan.json --channel launchd_clean --out book/experiments/probe-op-structure/out` → run id `39f84aa5-86b4-466d-b5d9-f510299bbd0a` (status: partial).
- File probe outcomes: `/tmp/foo` allowed; `/etc/hosts` denied with `open target: Operation not permitted` (apply ok, failure at probe stage). Unsandboxed observation records `/private/etc/hosts`, suggesting a canonicalization mismatch.
- Mach probe outcome: `com.apple.cfprefsd.agent` allowed via `sandbox_mach_probe`.
- IOKit probe outcome: `IOUSBHostInterface` not found (`stdout: {"found":false}`), so the sandboxed probe exits nonzero; treat as non-discriminating for policy semantics.
- Runtime-closure cross-check: `book/experiments/runtime-closure/out/5a8908d8-d626-4cac-8bdd-0f53c02af8fe/` file lane shows `/etc/hosts` denied across alias-only, private-only, and both profiles; `/private/etc/hosts` allowed only when explicitly allowed; `/tmp/foo` denied across all profiles. `path_witnesses.json` baseline resolves `/etc/hosts` -> `/private/etc/hosts` and `/tmp/foo` -> `/private/tmp/foo`, and scenario success shows `F_GETPATH_NOFIRMLINK:/System/Volumes/Data/private/etc/hosts` for `/private/etc/hosts`.
- Runtime-closure mach lane run `book/experiments/runtime-closure/out/66315539-a0ce-44bf-bff0-07a79f205fea/`: `com.apple.cfprefsd.agent` allowed in baseline and scenario; `com.apple.sandbox-lore.missing` returns `kr=1102` in baseline and scenario, confirming the missing-service control behaves the same without the sandbox.
- Runtime-closure IOKit lane run `book/experiments/runtime-closure/out/48086066-bfa2-44bb-877c-62dd1dceca09/`: baseline `IOSurfaceRoot` opens (`open_kr=0`), scenario `sandbox_iokit_probe` reports `open_kr=-536870174` with `EPERM`, giving a discriminating IOKit signal on this host.
- Runtime-closure file matrix run `book/experiments/runtime-closure/out/ea704c9c-5102-473a-b942-e24af4136cc8/` (v2 spellings):
  - Alias profile denies all six probes; private profile allows `/private/...` and `/System/Volumes/Data/private/...` spellings plus `/tmp/foo`; data profile denies all six.
  - `/etc/hosts` remains denied under alias spelling even when private and Data spellings are allowed; `/tmp/foo` is allowed when private spelling is allowed.
- Runtime-closure IOKit user-client run `book/experiments/runtime-closure/out/6ecc929d-fec5-4206-a85c-e3e265c349a7/`:
  - `IOSurfaceRootUserClient` allow rule (`v2_user_client_only`) flips `IOSurfaceRoot` to allow (`open_kr=0`).
  - Adding `IOAccelerator` connection constraint (`v3_connection_user_client`) returns `EPERM`.
- Runtime-closure IOKit op-identity micro-matrix runs `book/experiments/runtime-closure/out/08887f36-f87b-45ff-8e9e-6ee7eb9cb635/` and `book/experiments/runtime-closure/out/33ff5a68-262a-4a8c-b427-c7cb923a3adc/`:
  - Both `iokit-open-user-client` (v2) and `iokit-open` (v4) allow `IOSurfaceRoot` at operation stage, so op identity remains ambiguous.
- Runtime-closure IOKit op-identity tri-matrix run `book/experiments/runtime-closure/out/fae371c2-f2f5-470f-b672-cf0c3e24d6c0/`:
  - `v5_service_only` and `v6_user_client_only` both deny `IOSurfaceRoot` with `open_kr=-536870174` (EPERM).
  - `v7_service_user_client_both` allows `IOSurfaceRoot` (`open_kr=0`) but the post-open call fails (`call_kr=-536870206`).
  - Unsandboxed `iokit_probe IOSurfaceRoot` also reports `call_kr=-536870206`, so the post-open action is not discriminating on this host.
