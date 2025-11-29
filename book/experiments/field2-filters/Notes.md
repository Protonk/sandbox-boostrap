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
