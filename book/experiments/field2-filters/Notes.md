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

## 2026-02-12

- Located the kernel evaluator in the sandbox fileset: `FUN_ffffff8002d8547a` in `com.apple.security.sandbox` (`vmaddr 0xffffff8002d70000`, fileoff `0x02c68000`, text span `0xffffff8002d71208–0xffffff8002da9f7f`). It drives the opcode switch and calls helper readers `FUN_ffffff8002d87d4a`, `FUN_ffffff8002d87d8f`, `FUN_ffffff8002d8809a`, `FUN_ffffff8002d8907f` to load edges/`field2`. High-level decompile shows `field2` forwarded directly from `FUN_2d87d4a`; any hi-bit/lo-bit handling likely lives inside these helpers.
- Tooling state: `objdump`/`llvm-objdump` on the KC ignored the fileset entry; byte-slicing by fileoff produced “truncated/malformed object.” Need to extract the sandbox fileset (`kmutil emit-macho` or custom unwrapping) to disassemble helper functions and search for `tbz`/`tbnz`/`ubfx`/`and` masks on the payload register.
- Follow-up disassembly (fileset carve):
  - Parsed LC_FILESET_ENTRY to get the sandbox slice (fileoff `0x2c70000`, size `503808`), carved it, and locally fixed load-command file offsets/symtab to enable disassembly (`/tmp/sandbox_kext_fixed.bin`).
  - `FUN_ffffff8002d87d4a`: bounds-checks and `movzwl` a u16 from the profile byte array into a caller-provided pointer; no masks/bit-tests.
  - `FUN_ffffff8002d87d8f`/`FUN_ffffff8002d8809a`: wrappers around `2d87d4a` that scale/advance pointers; still no masking or `test/and` on the loaded u16.
  - No `testw $0x4000`/`and $0x3fff`/`ubfx`-style operations observed in these helpers or nearby snippets; suggests `field2` is consumed raw in this x86_64 KC. Need to repeat on the arm64e fileset (Apple Silicon target) to confirm the same behavior.
- Arm64e follow-up attempt: `kmutil emit-macho --arch arm64e` still produced an x86_64 KC (`cputype` 16777223), and the carved sandbox slice shows x86_64 headers. No arm64e slice available in this BootKC dump, so the helper scan currently only covers the x86_64 view.

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

### Mixed-network and bsd-context probes

- `flow_divert_mixed.sb` (network in/out + flow-divert literal + mach-lookup) compiled via `sbsnarf.py`: op_count=2, node_count=29, tags {0,1}, field2 collapsed to {1×29}; no flow-divert literal refs surfaced in nodes and 2560 did not appear.
- `bsd_tail_context.sb` (dtracehelper + posix_spawn literals with simple allow/deny) compiled via `sbsnarf.py`: op_count=4, node_count=29, tags {0,1,3}, field2 {3×27, 1×2}; nodes referencing the literals carry only low field2 values. High bsd tail values (170/174/115/109/16660) remain absent outside the full profile.

### 2560 re-check and anchor sweep

- Revalidated 2560 signal in original mixed network probes (`v4_network_socket_require_all`, `v7_file_network_combo`): both still show field2 values dominated by 8/7 with a single node carrying 2560 (tag 0, fields [0,0,2560,0,7]) tied to `com.apple.flow-divert`. A simplified require-any clone collapsed field2 to low IDs and was discarded.
- Anchor sweep (existing probe-op-structure outputs) remains unchanged: anchors mostly map to generic path/name field2 values; `flow-divert` anchor still pairs with {7, 2560, 2} but only in the richer probes, not in the new simplified ones.

### Bsd-tail mimic with extra op

- Tweaked `bsd_tail_context.sb` to add a mach-lookup rule alongside dtracehelper/posix_spawn literals. Compile/decode shows op_count=4, node_count=29, tags {0,1,3}, field2 {3×27, 1×2}. Literal-bearing nodes still carry only low IDs. High bsd tail values (170/174/115/109/16660) remain locked to the full bsd profile; adding a mach rule did not surface them.

### Hi/lo census refresh and probe-op inclusion

- Updated `harvest_field2.py` to treat the third slot explicitly as `filter_arg_raw` with derived `field2_hi = raw & 0xC000` and `field2_lo = raw & 0x3FFF`, and to track per-tag counts. Inventory now ingests `book/experiments/probe-op-structure/sb/build` profiles alongside the local probes and system blobs; refreshed output lives at `out/field2_inventory.json`.
- Hi/lo observations: all current unknowns except the bsd tail carry `hi=0`; bsd’s 16660 shows `hi=0x4000`, `lo=0x114`. Unknowns 2560 (flow-divert), 10752/166/165 (airlock), and 170/174/115/109 (bsd) all keep `hi=0` and remain unmapped.
- Tag context from the new census: airlock’s 166/165 live on tags {166,1} with 10752 on tag 0; bsd’s 170/174/115/109 cluster on tag 26, while 16660 sits on tag 0 (shared tail); flow-divert 2560 appears once each in `v4_network_socket_require_all` and `v7_file_network_combo` on tag 0, and still does not show up in the simplified `flow_divert_*` variants (which collapse to low IDs).
- Negative notes: `v8_all_combo.sb.bin` decodes to `node_count=0` in this pass; `flow_divert_mixed.sb.bin` continues to collapse to a single low-ID path-ish node (`mount-relative-path`).
- Added per-profile `unknown_nodes` capture in `out/field2_inventory.json` (nodes with `hi != 0` or no vocab match). This shows concrete field arrays and literal refs for the high/unknown cases (bsd 16660/170/174/115/109, airlock 165/166/10752, flow-divert 2560, sample’s 3584). No graph-walk or predecessor counts yet; edge layout ambiguity blocked that for now.

### Focused unknown-node census and new probes (2026-02-11)

- Added `unknown_focus.py` to emit a focused table of high/unknown nodes with fan-in/out based on tag layouts (edges at fields 0/1). Output at `out/unknown_nodes.json` confirms:
  - bsd: 16660 on tag 0 has fan_in=33, fan_out=1 (second edge is out-of-bounds 3840); other high values (170/174/115/109) live on tag 26 with fan_out=1, fan_in=0.
  - airlock: 166/165/10752 remain, mostly on tag 166/1; some nodes are self-loops with no valid fan-out.
  - flow-divert 2560 nodes in `v4`/`v7` have fan_out=2 (both edges 0), fan_in=0; sample’s 3584 likewise.
- New probes:
  - `flow_divert_variant.sb` (network in/out + flow-divert literal + mach-lookup + file-read) compiled via absolute path; decoded to only low IDs (`mount-relative-path`), losing the 2560 signal. Negative.
  - `bsd_broader.sb` (multiple bsd-ish literals, mach-lookup, network in/out) compiled via absolute path; decoded to low IDs only (local/local-name/path/xattr/global-name/file-mode), no high field2 values surfaced. Negative.
- sbsnarf.py requires absolute paths for compilation on this host; relative paths returned “profile not found.” Documented behavior for future runs.

### Execution note (2026-02-11)

- Kernel path not executed in this session: Ghidra is available, but the evaluator/mask hunt remains to be done; kept as the next high-value action.
- No further probe variants attempted beyond `flow_divert_variant` and `bsd_broader`; if future mixed-network perturbations also collapse to low IDs, stop that branch and move kernel-side.

### Kernel mask and immediate scans (2026-02-11)

- Ran `kernel_field2_mask_scan` twice on the 14.4.1 project:
  - Sandbox blocks only (default masks 0x3fff/0x4000/0xc000): no hits.
  - Full-program with masks 0x3fff/0x4000/0xc000/0x00ff/0xff00: no hits. Output at `dumps/ghidra/out/14.4.1-23E224/kernel-field2-mask-scan/mask_scan.json`.
- Ran `kernel_imm_search` on key field2 constants across the full KC: 0xa00 (flow-divert 2560), 0x4114 (bsd tail hi-bit), and 0x2a00 (airlock high). All returned zero hits. Outputs under `dumps/ghidra/out/14.4.1-23E224/kernel-imm-search/`. These negatives suggest the constants are not present as plain immediates; evaluator likely derives flags via other arithmetic or indirect tables.

## Ghidra pointer

- Target binary: `Sandbox.kext` on 14.4.1 (Apple Silicon), load the kext’s main binary in Ghidra (ARM64).
- Goal: find the policy graph evaluator that walks node records and consumes the third 16-bit payload (`field2`/filter_arg).
- Searches: look for masks/shifts like `& 0x3FFF`, `& 0x4000`, `& 0xC000` applied to a u16 loaded from a node; also look for op-table indexing and node-array traversal. Start from `sandbox_check`/`sandbox_check_bulk` or MACF hooks and follow to per-node dispatch.
- Extract: confirm node layout (offsets for tag, edges, field2), whether `field2` is split into flags/index, any flag checks (e.g., `& 0x4000`), and any table indexing using the low bits. These masks/branches will be the authoritative semantics for the high values (2560/16660/etc.).

## binutils handover

• The sandbox arm64e kext is now extracted cleanly with ipsw: /tmp/sandbox_arm64e/ com.apple.security.sandbox (Mach-O arm64e, __text offset 155,648, size 262,856, vmaddr 0xfffffe000b3f34f0). Using GNU binutils (/opt/homebrew/opt/binutils/bin/objdump) on the raw __text bytes:

* FUN_ffffff8002d87d4a (reader): loads a u16 from the profile buffer after bounds checks. Key sequence: ldrb w?, checks length, ldr x? [x?], ldrh/mov to store into caller’s pointer, returns. No and/tbz/ubfx; the u16 is passed through unmasked.
* FUN_ffffff8002d87d8f and FUN_ffffff8002d8809a are wrappers that call 2d87d4a, add offsets, and propagate the u16. Again, no bit tests or masks on the loaded value.
* FUN_ffffff8002d8907f (used in the evaluator loop) likewise uses 2d87d4a to fetch the payload and drives comparisons/branching without masking the field.
* Scanned nearby code with objdump for tbz/tbnz/and/ubfx on the registers holding the payload: none found in these helpers. No & 0x3fff/& 0x4000 semantics evident in the arm64e helpers.

Status: On arm64e (the actual Apple Silicon KC), the helper that reads field2 returns it raw; there is no hi-bit or low-bit masking at the load/dispatch layer. Field2 semantics are not split in the helpers; any special handling would have to be elsewhere (e.g., higher-level logic).

Notes/Report updated: recorded that ipsw extraction works, the arm64e helpers show raw field2 (no masks), and the previous x86_64-only caveat is resolved.

Next steps: If needed, scan the main evaluator (FUN_ffffff8002d8547a in arm64e) for any downstream bit tests on the register loaded by 2d87d4a; based on helper behavior, it likely also consumes field2 raw.

## Recent updates

- Arm64e scan: disassembled `__TEXT_EXEC.__text` for mask constants; only `0x3fff` uses live in `_syscall_extension_issue`, not in the graph evaluator. `_sb_evaluate_internal` shows no masking/shifting of node payloads, consistent with the helper returning a raw u16.
- Flow-divert peel: added `net_require_all_*` variants. `field2_inventory.json` shows 2560 only when `(socket-domain AF_INET) + (socket-type SOCK_STREAM) + (socket-protocol IPPROTO_TCP)` are required together; any pair of predicates drops 2560 and collapses to low IDs. Literal `com.apple.flow-divert` stays attached to the 2560 node in the triple.
- Unknown-focus rev: script now adds op-table reachability and sweeps all probes. `unknown_nodes.json` shows `bsd`’s 16660 tail reachable from op IDs 0–27 (default/file* cluster); other bsd highs remain op-empty. Airlock’s 165/166/10752 nodes hang off op 162 (`system-fcntl`). Flow-divert 2560 nodes remain op-empty.
