# Field2 ↔ Filter Mapping – Research Report (Sonoma / macOS 14.4.1)

## Purpose
Decode the meaning of `field2` values in decoded PolicyGraph nodes by aligning them with the harvested Filter Vocabulary. Use targeted SBPL probes and system profiles to establish a stable mapping of `field2` ↔ filter-ID on this host.

## Baseline & scope
- Host: macOS 14.4.1 (23E224), Apple Silicon, SIP enabled (same as other experiments).
- Vocab artifacts: `book/graph/mappings/vocab/filters.json` (93 entries, status: ok), `ops.json` (196 entries, status: ok).
- Canonical blobs for cross-check: `book/examples/extract_sbs/build/profiles/airlock.sb.bin`, `bsd.sb.bin`, `sample.sb.bin`.

## Deliverables / expected outcomes
- `book/experiments/field2-filters/out/field2_inventory.json` capturing `field2` histograms and hi/lo splits across canonical system profiles and synthetic probes.
- `book/experiments/field2-filters/out/unknown_nodes.json` (and related census outputs) describing high/unknown `field2` values with tag context and fan-in/fan-out counts.
- A provisional table of `field2` → filter-name/ID correspondences, with explicit provenance and validation status per mapping, to be shared once stable.
- Notes in this report and `Notes.md` summarizing generic path/name behavior versus high/unknown cases so other experiments can consume `field2` responsibly.
- (Planned) a small guardrail covering a handful of stable `field2` ↔ filter mappings (path/socket/iokit families).

## Plan & execution log
### Completed
- **Current status**
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
- **1) Scope and setup**
  - Host baseline (OS/build, kernel, SIP) and canonical blobs recorded in `ResearchReport.md`.
  - Vocab artifacts (`book/graph/mappings/vocab/filters.json`, `ops.json`) confirmed `status: ok` (93 filters, 196 ops).
  - Canonical blobs for cross-check identified and used: `book/examples/extract_sbs/build/profiles/airlock.sb.bin`, `bsd.sb.bin`, `sample.sb.bin`.
- **2) Baseline inventory**
  - Decoded canonical blobs and tallied unique `field2` values; baseline histograms recorded in `ResearchReport.md` and `Notes.md`. Refreshed the census to include hi/lo splits and per-tag counts, and pulled in mixed probe-op-structure builds to keep flow-divert and other richer shapes in view.
  - Confirmed that many `field2` values align directly with filter vocab IDs (e.g., path/socket/iokit filters in `bsd` and `sample`), with high unknowns in `airlock`.
- **3) Synthetic single-filter probes**
  - Authored single-filter SBPL variants (subpath, literal, global-name, local-name, vnode-type, socket-domain, iokit-registry-entry-class, require-any mixtures) and compiled them under `sb/build/`; added probe-op-structure mixed-operation builds to keep the flow-divert 2560 signal available for comparison.
  - Decoded each variant and recorded `field2` values; synthesized into `out/field2_inventory.json`.
- **4) Cross-op consistency checks**
  - Checked that low `field2` IDs corresponding to path/name filters (0,1,3,4,5,6,7,8) behave consistently across system profiles and synthetic probes.
  - Confirmed that system profiles (`bsd`, `sample`) reinforce the mapping for common filters (preference-domain, right-name, iokit-*, path/socket).
- **5) System profile cross-check**
  - Inspected curated system profiles where literals strongly indicate filter type (paths, mach names, iokit properties) and confirmed that `field2` IDs match vocab entries where known.
- **6) Synthesis and guardrails**
  - Summarized current understanding of `field2` behavior (generic path/name dominance, confirmed mappings for common filters, persistence of unknowns) in `ResearchReport.md` and `Notes.md`.
  - Regenerated `out/field2_inventory.json` using shared tag layouts and anchor/filter mappings to keep inventories aligned with the global IR.
  - Added arm64e helper scan: field2 reader and wrappers return raw u16 with no masking; `objdump` scan for `0x3fff/0x4000` in `__TEXT_EXEC` only hits `_syscall_extension_issue`, not the graph evaluator. `_sb_evaluate_internal` disassembly shows no bit tests on node payloads.
  - Probed flow-divert shape by peeling socket predicates: new `net_require_all_*` variants show 2560 only when `(socket-domain AF_INET) + (socket-type SOCK_STREAM) + (socket-protocol IPPROTO_TCP)` are required together; any pair drops back to low IDs. The `com.apple.flow-divert` literal stays attached to the 2560 node in the triple.
  - Refreshed `unknown_focus.py` to include op-table reachability across all probes. `unknown_nodes.json` now shows bsd’s 16660 tail reachable from op IDs 0–27 (default/file* cluster), bsd’s 170/174/115/109 still op-empty, airlock’s 165/166/10752 attached to op 162 (`system-fcntl`), and flow-divert 2560 nodes op-empty.

### Planned
- 1. **Baseline inventory**: Decode canonical blobs, tally `field2` values per node tag, and see which op-table entries reach which values.
  2. **Single-filter probes**: Build tiny SBPL profiles, each exercising one filter (subpath, literal, global-name, local-name, vnode-type, socket-domain, iokit-registry-entry-class, etc.), then record `field2` from graph walks.
  3. **Cross-op checks**: For filters used by multiple operations, ensure `field2` is stable across ops; flag inconsistencies.
  4. **System profile cross-check**: Use literals in system profiles (paths, mach names) to confirm the mapping.
  5. **Synthesis**: Summarize the mapping with evidence and add guardrail tests.
- **1) Scope and setup**
  - Keep baseline/version notes updated if the host or vocab artifacts change.
  - Continue to carry the third node slot explicitly as `filter_arg_raw` with derived `field2_hi/field2_lo`; do not coerce high/unknown values into the existing filter vocabulary.
  - `Plan.md`, `Notes.md`, `ResearchReport.md` in this directory.
  - A small helper script to collect `field2` values from decoded profiles.
- **2) Baseline inventory**
  - Refine per-tag/per-op inventories using newer decoder layouts if needed.
  - Intermediate JSON/notes summarizing `field2` histograms and per-op reachable values.
- **3) Synthetic single-filter probes**
  - Design additional probes that reduce or alter generic path/name scaffolding (e.g., richer operations or more complex metafilters) to surface filter-specific `field2` values; keep richer network shapes when chasing flow-divert (simplified profiles collapsed field2 to low IDs and lost 2560; richer mixes like v4/v7 retain 2560). Treat hi/lo views as diagnostic only until kernel bitfields are known.
  - `sb/` variants + compiled blobs under `sb/build/`.
  - Notes mapping filter name → observed `field2` value(s) with provenance.
- **4) Cross-op consistency checks**
  - Perform focused cross-op checks for less common filters once better probes or anchors are available; chase the flow-divert-specific field2 (2560) using richer network mixes, and any other high/unknown values by varying operations. Simplified dtracehelper/posix_spawn probes yielded only low IDs, so full-profile context may be required; adding mach to the mimic still did not surface high IDs. Use graph shape/position as the primary classifier, with `field2_hi/lo` treated as auxiliary evidence only.
  - Flag and investigate any inconsistencies that appear as decoding improves.
  - Table of filter → `field2` with cross-op status (consistent/inconsistent).
- **5) System profile cross-check**
  - Use anchor mappings and updated tag layouts to deepen system-profile cross-checks, especially for high, currently-unknown `field2` values in `airlock` and the `bsd` tail (e.g., 170/174/115/109/16660 tied to dtracehelper/posix_spawn literals that did not reappear in isolated probes). Track `(tag, field2_hi, field2_lo)` distributions for these cases without assigning semantics yet.
  - Notes tying system-profile nodes to the inferred mapping.
- **6) Synthesis and guardrails**
  - Distill a stable `field2` ↔ filter-ID table for a small, high-confidence subset of filters; attempt to promote flow-divert-related values and high system-profile values only once additional probes and/or Sandbox.kext bitfields confirm them.
  - Add a guardrail test/script that checks these mappings against synthetic profiles once the semantic layer is better understood; for now, keep high/unknown values in an “unknown-arg” bucket.
  - Extend `ResearchReport.md` with any newly established mappings and explicit open questions, noting where conclusions rely on hi/lo heuristics versus kernel evidence.

## Evidence & artifacts
- Canonical system profiles `airlock.sb.bin`, `bsd.sb.bin`, and `sample.sb.bin` decoded via `book.api.decoder`.
- Synthetic single-filter and mixed-profile SBPL variants under `sb/` with compiled blobs in `sb/build/`.
- `book/experiments/field2-filters/out/field2_inventory.json` (baseline and refreshed hi/lo census plus per-tag counts).
- `book/experiments/field2-filters/out/unknown_nodes.json` produced by `unknown_focus.py` with focused statistics on high/unknown `field2` nodes.
- Supporting scripts such as `harvest_field2.py` and `unknown_focus.py`, plus detailed provenance in `Notes.md`.

## Blockers / risks
- High and unknown `field2` values (e.g., flow-divert 2560, `bsd` 16660, and `airlock` 165/166/10752) remain unmapped and only appear reliably in full system profiles or rich mixed probes.
- Generic path/name scaffolding dominates most synthetic profiles, making filter-specific `field2` signals hard to isolate without carefully designed SBPL shapes.
- Tag layouts (especially for higher tags such as 26/27) are still partially understood, so misinterpreting payload fields versus edge fields remains a risk when inferring semantics.

## Next steps
- Capture a clean dump of the arm64e evaluator function (the loop calling the field2 reader) for provenance, and continue scanning its surroundings for any non-literal bitfield handling if new evidence appears.
- For flow-divert, try minor perturbations of the triple-socket profile (e.g., reorder filters, add/remove default deny/allow clauses) to see if op-table reachability for the 2560 node can be surfaced; record the minimal op/graph context that still carries the literal and payload.
- Use the updated `unknown_nodes.json` (with op reach) to design bsd/airlock probes that mirror the originating ops: bsd tail is reachable from the default/file* cluster (ops 0–27), airlock unknowns from op 162 (`system-fcntl`). Target those ops explicitly rather than only literals to chase the high field2 values outside the full profiles.
- Once a small set of mappings is stable, promote them into a shared `field2` mapping artifact and add guardrails that assert those mappings on curated reference blobs.

## Appendix
### Current wrinkle: synthetic profiles and field2 skew
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

### Updates (2025-12-12)
- Regenerated `out/field2_inventory.json` after publishing shared tag layouts and anchor/filter mappings. Anchor entries now carry mapped filter IDs where available (e.g., `preferences/logging` → global-name, `/etc/hosts` shows path/mount-relative-path alongside sentinel 3584).
- System profiles unchanged in structure; high-value unknowns in `airlock` persist. Synthetic probes remain dominated by generic path/name filters (global-name, ipc-posix-name, file-mode, local-name).
- Next steps: leverage anchor-filter map to reinterpret anchor-bearing nodes and design richer probes/ops to surface non-generic filters; consider cross-op comparisons using updated tag layouts.

### Recent update (tag-aware scan)
- Re-ran tag-aware decoding on existing single-filter probes and anchor-heavy probes (`probe-op-structure` builds). Single-filter probes remain dominated by generic path/name filters: field2 stays in {0,3,4,5,6,7,8} with no new signal.
- Network/flow-divert probes surfaced a distinct but still-unmapped field2 value: nodes linked to the literal `com.apple.flow-divert` carry field2 values 7 (`local`), 2 (`xattr`), and an unknown 2560 on tag 0 (edges 0,0, payload 2560). The same 2560 node appears in both `v4_network_socket_require_all` and `v7_file_network_combo`, suggesting 2560 is tied to flow-divert-specific logic rather than generic path/name scaffolding. Minimal or simplified profiles (flow_divert_only, flow_divert_mixed) collapse the field2 space to low IDs (1/2) and lose 2560, implying the richer mixed-profile shape is required.
- Network/flow-divert probes surfaced a distinct but still-unmapped field2 value: nodes linked to the literal `com.apple.flow-divert` carry field2 values 7 (`local`), 2 (`xattr`), and an unknown 2560 on tag 0 (edges 0,0, payload 2560). The same 2560 node appears in both `v4_network_socket_require_all` and `v7_file_network_combo`, suggesting 2560 is tied to flow-divert-specific logic rather than generic path/name scaffolding. Minimal or simplified profiles (flow_divert_only, flow_divert_mixed, require-any clone) collapse the field2 space to low IDs and lose 2560, implying the richer mixed-profile shape is required to surface it.
- System profiles:
  - `bsd.sb.bin` shows high field2 values (174, 170, 115, 109, 16660) on tag-26/0 nodes tied to literals like `/dev/dtracehelper` and `posix_spawn_filtering_rules`; still unmapped. Targeted probes (dtracehelper_posixspawn, bsd_tail_context) only produced low/generic field2 values ({1,3,4,5}), so the high values remain elusive outside the full profile.
  - `airlock.sb.bin` remains high-value only (165/166/10752) with sparse literals (`G/system/`, `IOMediaIcon`), no new mapping.
- No guardrails added; ambiguity persists for the new high/unknown field2 values. Next probes should retain the richer network profile shape to keep 2560 visible, or find a different angle on the bsd tail values if single-literal probes continue to collapse to generic IDs.

### Hi/lo census refresh (probe-op inclusion)
- `harvest_field2.py` now treats the third node slot explicitly as `filter_arg_raw` and emits derived views (`field2_hi = raw & 0xC000`, `field2_lo = raw & 0x3FFF`) plus per-tag counts. The refreshed `out/field2_inventory.json` also pulls in the mixed-operation builds under `book/experiments/probe-op-structure/sb/build` to keep the flow-divert signal visible.
- Hi/lo observations: all current unknowns keep `hi=0` except for the bsd tail node, which shows `hi=0x4000`, `lo=0x114` (16660 raw). Unknowns 2560 (flow-divert), 10752/166/165 (airlock), and 170/174/115/109 (bsd) retain `hi=0` and remain unmapped.
- Tag context: airlock’s 166/165 cluster on tags {166,1} with 10752 on tag 0; bsd’s 170/174/115/109 cluster on tag 26, while 16660 sits on tag 0 (shared sink); flow-divert 2560 appears once each in `v4_network_socket_require_all` and `v7_file_network_combo` on tag 0 and remains absent from simplified `flow_divert_*` variants. `v8_all_combo.sb.bin` decodes to `node_count=0` in this pass; `flow_divert_mixed.sb.bin` still collapses to a single low-ID (`mount-relative-path`).
- `field2_inventory.json` now includes `unknown_nodes` entries (hi != 0 or no vocab match) with tags, raw field arrays, and literal refs, to make the high/unknown cases easier to track without hand-walking the graphs. No predecessor/fan-in counts yet; edge layout ambiguity blocked graph-walk classifiers in this pass.

### Recent probes and focused census (2026-02-11)
- Added `unknown_focus.py` to emit a focused table of high/unknown nodes with fan-in/out counts using tag layouts (edges at fields 0/1). Output (`out/unknown_nodes.json`) shows:
  - `bsd`: 16660 on tag 0 has fan_in=33, fan_out=1 (second edge out of bounds); 170/174/115/109 sit on tag 26 with fan_out=1, fan_in=0.
  - `airlock`: 166/165/10752 remain unmapped, mostly tag 166/1, some self-loops, no clear fan-out.
  - Flow-divert 2560 nodes in `v4`/`v7` have fan_out=2 (edges 0/0), fan_in=0; `sample`’s 3584 similarly unreferenced.
- New mixed probes:
  - `flow_divert_variant.sb` (network in/out + flow-divert literal + mach-lookup + file-read) compiled with absolute paths; decoded to low IDs only (mount-relative-path), losing the 2560 signal. Negative.
  - `bsd_broader.sb` (multiple bsd-ish literals + mach-lookup + network in/out) compiled; decoded to low IDs only (local/local-name/path/xattr/global-name/file-mode), no high field2 values surfaced. Negative.
- Tooling note: `sbsnarf.py` requires absolute SBPL paths on this host; relative paths produced “profile not found.”

### Kernel evaluator pivot (current thread)
- Main evaluator identified as `FUN_ffffff8002d8547a` inside the sandbox fileset entry (`vmaddr 0xffffff8002d70000`, fileoff `0x02c68000`, text span `0xffffff8002d71208–0xffffff8002da9f7f`). It performs the opcode switch/node walk and calls helper readers `FUN_ffffff8002d87d4a`, `FUN_ffffff8002d87d8f`, `FUN_ffffff8002d8809a`, `FUN_ffffff8002d8907f` to load node fields (edges plus `field2`/payload). High-level decompile shows `field2` flowing directly from `FUN_2d87d4a`; any hi-bit/lo-bit handling would live inside these helpers.
- Fileset carve + disassembly: parsed LC_FILESET_ENTRY to carve the sandbox slice (fileoff `0x2c70000`, size `503808`), patched load-command offsets/symtab locally (`/tmp/sandbox_kext_fixed.bin`), and disassembled the helpers. `FUN_2d87d4a` bounds-checks and `movzwl` a u16 from the profile byte array into a caller-provided pointer; `FUN_2d87d8f`/`FUN_2d8809a` wrap it to advance pointers/scale indices. No `test/and` on 0x4000/0x3fff or other bitfield extraction observed in these helpers, suggesting `field2` is consumed raw in this KC (x86_64 build).
- Architecture caveat: both the original KC and the carved sandbox slice report `cputype` 16777223 (x86_64). `kmutil emit-macho --arch arm64e` did not produce an arm64e slice, so current helper evidence is x86_64-only; an arm64e view is unavailable in this dump.
