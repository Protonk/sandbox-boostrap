# Field2 ↔ Filter Mapping – Notes

Use this file for dated, concise notes on progress, commands, and intermediate findings.

## 2025-12-03

- Experiment initialized. Vocab artifacts available (`filters.json` 93 entries, `ops.json` 196 entries). Pending: baseline `field2` inventory from canonical blobs and synthetic single-filter probes.
- Baseline `field2` inventory:
  - `airlock.sb.bin`: node_count 7; field2 values {166×5, 10752×1, 165×1} (no vocab hits).
  - `bsd.sb.bin`: node_count 41; field2 values {27×24, 26×5, 18×1, 17×1, 5×1, 16660×1, 174×1, 1×1, 109×1, 11×1, 170×1, 15×1, 115×1, 80×1}. Vocab hits include 27=preference-domain, 26=right-name, 18=iokit-connection, 17=iokit-property, 5=global-name, 1=mount-relative-path, 11=socket-type, 15=ioctl-command, 80=mac-policy-name.
  - `sample.sb.bin`: node_count 32; field2 values {8×19, 7×9, 3×1, 1×1, 0×1, 3584×1}. Vocab hits include 8=remote, 7=local, 3=file-mode, 1=mount-relative-path, 0=path. 3584 unknown/sentinel.

## 2025-12-07

- Added `harvest_field2.py` output for all single-filter probes under `sb/build` plus system profiles; artifact now lives at `out/field2_inventory.json`.
- Observations:
  - System profiles reaffirm vocab alignment: `bsd` maps field2 IDs directly to filter names (preference-domain/right-name/iokit-*), `sample` maps low IDs to path/socket filters, `airlock` carries high unknowns (166/165/10752).
  - Single-filter probes still surface generic path/name filters regardless of intended filter (subpath/literal/vnode-type all show field2 {5,4,3}; socket-domain shows {6,5,0}). Suggests graph walks are dominated by shared scaffolding; filter-specific IDs are masked in these tiny profiles.
- Next steps: design probes with stronger anchors or use improved decoder/anchor mapping from probe-op-structure once literal bindings surface.

## 2025-12-09

- Decoder/anchor improvements now bind anchors to nodes in simple probes (via probe-op-structure), but those nodes still carry generic field2 values (global-name/local-name/path). Filter-specific IDs remain masked; need richer tag decoding and anchor-strong probes to isolate them.
- `harvest_field2.py` now threads anchor hits (when present in probe-op-structure outputs) into `out/field2_inventory.json`; system profiles carry anchor hits, probe profiles remain anchor-empty.

## 2025-12-11

- New shared artifacts unblocking deeper mapping: tag layouts published at `book/graph/mappings/tag_layouts/tag_layouts.json` and anchor → filter map at `book/graph/mappings/anchors/anchor_filter_map.json`. Use these to reinterpret anchor-bearing nodes and rerun `harvest_field2.py` for clearer filter IDs.

## 2025-12-12

- Re-ran `harvest_field2.py` with fixed import path; `out/field2_inventory.json` refreshed. Anchors now show mapped filter names/IDs where available (e.g., `preferences/logging` → global-name). Synthetic probes still dominated by generic path/name field2 values; high unknowns remain in `airlock`.

### Recent update

- Ran tag-aware decoding across single-filter probes and anchor-heavy probes (from probe-op-structure). Single-filter profiles still only surface generic path/name field2 values ({0,3,4,5,6,7,8}); no new filter-specific IDs.
- Network/flow-divert probes surfaced a repeatable but unmapped field2: nodes tied to literal `com.apple.flow-divert` carry field2 7 (`local`), 2 (`xattr`), and an unknown 2560 (tag 0, edges 0/0, payload 2560). The 2560 node appears in both `v4_network_socket_require_all` and `v7_file_network_combo`, suggesting a flow-divert-specific filter or branch.
- System profiles recap: `bsd.sb.bin` still shows high, unmapped field2 values (170/174/115/109/16660) on tag-26/0 nodes linked to literals such as `/dev/dtracehelper` and `posix_spawn_filtering_rules`; `airlock` remains high-valued only (165/166/10752) with sparse literals.
- Proposed probes: a minimal flow-divert SBPL to isolate 2560 without file scaffolding; a small dtracehelper/posix_spawn-focused profile to chase the `bsd` high field2 values under simpler graphs.

### 2026-01 follow-up probes

- `flow_divert_only.sb` (network-only, flow-divert literal) compiled via `sbsnarf.py`: op_count=3, node_count=28, tag 2 only, field2 values {2×26, 1×2}; the unknown 2560 did not appear. Literal refs still show `com.apple.flow-divert`, but simplifying the profile collapsed the field2 space to {1,2}.
- `dtracehelper_posixspawn.sb` (literals `/dev/dtracehelper`, `/usr/share/posix_spawn_filtering_rules`) compiled via `sbsnarf.py`: op_count=6, node_count=30, tags {0,1,4,5}, field2 {5×20, 4×9, 3×1}; only generic path/name-style IDs, no high values (170/174/115/109/16660) surfaced.
- No guardrails added; both probes failed to surface the earlier unknowns. Next attempt would need a richer network profile to preserve the flow-divert 2560 node, or a different angle on the bsd tail values.
