# Field2 ↔ Filter Mapping – Research Report (Sonoma / macOS 14.4.1)

## Purpose

Decode the meaning of `field2` values in decoded PolicyGraph nodes by aligning them with the harvested Filter Vocabulary. Use targeted SBPL probes and system profiles to establish a stable mapping of `field2` ↔ filter-ID on this host.

## Baseline and scope

- Host: macOS 14.4.1 (23E224), Apple Silicon, SIP enabled (same as other experiments).
- Vocab artifacts: `book/graph/mappings/vocab/filters.json` (93 entries, status: ok), `ops.json` (196 entries, status: ok).
- Canonical blobs for cross-check: `book/examples/extract_sbs/build/profiles/airlock.sb.bin`, `bsd.sb.bin`, `sample.sb.bin`.

## Plan (summary)

1. **Baseline inventory**: Decode canonical blobs, tally `field2` values per node tag, and see which op-table entries reach which values.
2. **Single-filter probes**: Build tiny SBPL profiles, each exercising one filter (subpath, literal, global-name, local-name, vnode-type, socket-domain, iokit-registry-entry-class, etc.), then record `field2` from graph walks.
3. **Cross-op checks**: For filters used by multiple operations, ensure `field2` is stable across ops; flag inconsistencies.
4. **System profile cross-check**: Use literals in system profiles (paths, mach names) to confirm the mapping.
5. **Synthesis**: Summarize the mapping with evidence and add guardrail tests.

## Current status

- Experiment scaffold created (`Plan.md`, `Notes.md`, this report).
- Vocab artifacts available and will be used as ground truth for filter names/IDs.
- Baseline `field2` inventory (decoder-only) from canonical blobs:
  - `bsd.sb.bin`: numerous `field2` values with clear vocab hits (e.g., 27=`preference-domain`, 26=`right-name`, 18=`iokit-connection`, 17=`iokit-property`, 11=`socket-type`, 5=`global-name`, 1=`mount-relative-path`, 15=`ioctl-command`).
  - `sample.sb.bin`: low IDs align with path/socket naming (`0=path`, `1=mount-relative-path`, `3=file-mode`, `7=local`, `8=remote`); a sentinel-like `3584` appears once.
  - `airlock.sb.bin`: mostly high values (166, 165, 10752) with no vocab hits yet; likely tied to profile-specific filters or padding.
- First round of synthetic single-filter probes (`v0_subpath`, `v1_literal`, `v2_global_name`, `v3_local_name`, `v4_vnode_type`, `v5_socket_domain`, `v6_iokit_registry_class`, `v7_require_any_subpath_literal`) compiled via `libsandbox` and decoded successfully.
- Added `out/field2_inventory.json` via `harvest_field2.py`, which now reports both system profiles and all single-filter probes:
  - System profiles confirm that `field2` values line up with filter IDs/names from `filters.json` (e.g., `bsd` shows preference-domain/right-name/iokit-*; `sample` shows path/socket filters; `airlock` carries high, still-unknown IDs).
  - Single-filter probes remain dominated by generic path/name scaffolding in the aggregate histogram: subpath/literal/vnode-type variants all show `field2` {5,4,3} (global-name/ipc-posix-name/file-mode); socket-domain shows {6,5,0} (local-name/global-name/path). Filter-specific IDs are not yet surfaced in these tiny profiles via histogram alone.

Anchor-aware decoder integration from `probe-op-structure` is available: anchors now bind to nodes in simple probes (and `field2_inventory.json` includes any anchor hits), but the bound nodes still carry generic field2 IDs. Field2 mapping remains open pending richer tag decoding and anchor-strong probes.

## Expected outcomes

- A table mapping `field2` values to filter IDs/names with provenance (probes + system blobs).
- Confirmation (or refutation) that `field2` is a direct filter-ID encoding on this host.
- A minimal guardrail test to prevent regressions for key filters (subpath, literal, global-name, local-name).

## Current wrinkle: synthetic profiles and field2 skew

The initial single-filter probes did not cleanly separate `field2` values by filter in the way we expected:

- All of the tiny profiles compiled by `libsandbox` (`op_count` 6–7) produce very short op-tables; when we decode and tally `field2` across their nodes:
  - The dominant `field2` values are small IDs that already appear in canonical blobs for other reasons:
    - 5 → `global-name`
    - 4 → `ipc-posix-name`
    - 3 → `file-mode`
    - 0 → `path`
    - 6 → `local-name` (most visible in the `network-outbound` variant).
  - These IDs are present even in profiles intended to exercise structurally different filters (e.g., `subpath`, `literal`, `vnode-type`, `iokit-registry-entry-class`), which suggests that the nodes we are seeing along the short graph walks are dominated by generic path/name machinery rather than the filter-specific node we hoped to isolate.

Implications for the experiment:

- The small op-tables produced for these synthetic profiles do not give us a direct, easily readable “one filter ↔ one `field2`” mapping. Instead, `field2` is heavily influenced by shared infrastructure filters (path/name checks) that sit in front of or around the specific filter we are trying to probe.
- Simply looking at “all `field2` values reachable from the operation entry” in these profiles is not enough to assign a unique `field2` to each filter; the signal is a mixture of generic and specific filters.

Next steps (conceptual, without changing code yet):

- Use richer profiles (including system profiles with higher `op_count` and more diverse filters) and more selective graph walks to target nodes whose surrounding context clearly indicates a specific filter (e.g., path literals for `subpath`/`literal`, mach names for `global-name`/`local-name`).
- Treat the small synthetic profiles as structural sanity checks (confirming that low `field2` IDs like 0, 1, 3, 4, 5, 6 match known path/name filters), not as the sole evidence for a complete `field2` ↔ filter-ID mapping.

## Updates (2025-12-12)

- Regenerated `out/field2_inventory.json` after publishing shared tag layouts and anchor/filter mappings. Anchor entries now carry mapped filter IDs where available (e.g., `preferences/logging` → global-name, `/etc/hosts` shows path/mount-relative-path alongside sentinel 3584).
- System profiles unchanged in structure; high-value unknowns in `airlock` persist. Synthetic probes remain dominated by generic path/name filters (global-name, ipc-posix-name, file-mode, local-name).
- Next steps: leverage anchor-filter map to reinterpret anchor-bearing nodes and design richer probes/ops to surface non-generic filters; consider cross-op comparisons using updated tag layouts.

## Recent update (tag-aware scan)

- Re-ran tag-aware decoding on existing single-filter probes and anchor-heavy probes (`probe-op-structure` builds). Single-filter probes remain dominated by generic path/name filters: field2 stays in {0,3,4,5,6,7,8} with no new signal.
- Network/flow-divert probes surfaced a distinct but still-unmapped field2 value: nodes linked to the literal `com.apple.flow-divert` carry field2 values 7 (`local`), 2 (`xattr`), and an unknown 2560 on tag 0 (edges 0,0, payload 2560). The same 2560 node appears in both `v4_network_socket_require_all` and `v7_file_network_combo`, suggesting 2560 is tied to flow-divert-specific logic rather than generic path/name scaffolding. A minimal flow-divert-only profile collapsed field2 to {1,2}, so the 2560 signal seems to require the richer mixed-profile shape.
- System profiles:
  - `bsd.sb.bin` shows high field2 values (174, 170, 115, 109, 16660) on tag-26/0 nodes tied to literals like `/dev/dtracehelper` and `posix_spawn_filtering_rules`; still unmapped. A targeted dtracehelper/posix_spawn probe only produced generic field2 {3,4,5}, so the high values remain elusive outside the full profile.
  - `airlock.sb.bin` remains high-value only (165/166/10752) with sparse literals (`G/system/`, `IOMediaIcon`), no new mapping.
- No guardrails added; ambiguity persists for the new high/unknown field2 values. Next probes should retain the richer network profile shape to keep 2560 visible, or find a different angle on the bsd tail values if single-literal probes continue to collapse to generic IDs.
## Open questions

- Are any `field2` values context-dependent (e.g., change with meta-filters or op class)?
- Do some filters share `field2` values (unlikely, but needs evidence)?
- Does `field2` ever encode non-filter data in modern profiles?
