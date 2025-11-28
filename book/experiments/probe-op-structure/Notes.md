# Probe Op Structure – Notes

Use this file for dated, concise notes on probe designs, compile logs, and findings.

## 2025-12-03

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
