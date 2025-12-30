# Field2 ↔ Filter Mapping – Notes

Use this file for concise notes on progress, commands, and intermediate findings.

## Baseline inventory

- Experiment initialized. Vocab artifacts available (`filters.json` 93 entries, `ops.json` 196 entries). Pending: baseline `field2` inventory from canonical blobs and synthetic single-filter probes.
- Baseline `field2` inventory:
  - `airlock.sb.bin`: node_count 7; field2 values {166×5, 10752×1, 165×1} (no vocab hits).
  - `bsd.sb.bin`: node_count 41; field2 values {27×24, 26×5, 18×1, 17×1, 5×1, 16660×1, 174×1, 1×1, 109×1, 11×1, 170×1, 15×1, 115×1, 80×1}. Vocab hits include 27=preference-domain, 26=right-name, 18=iokit-connection, 17=iokit-property, 5=global-name, 1=mount-relative-path, 11=socket-type, 15=ioctl-command, 80=mac-policy-name.
  - `sample.sb.bin`: node_count 32; field2 values {8×19, 7×9, 3×1, 1×1, 0×1, 3584×1}. Vocab hits include 8=remote, 7=local, 3=file-mode, 1=mount-relative-path, 0=path. 3584 unknown/sentinel.

## Single-filter probes and inventory

- Added `harvest_field2.py` output for all single-filter probes under `sb/build` plus system profiles; artifact now lives at `out/field2_inventory.json`.
- Observations:
  - System profiles reaffirm vocab alignment: `bsd` maps field2 IDs directly to filter names (preference-domain/right-name/iokit-*), `sample` maps low IDs to path/socket filters, `airlock` carries high unknowns (166/165/10752).
  - Single-filter probes still surface generic path/name filters regardless of intended filter (subpath/literal/vnode-type all show field2 {5,4,3}; socket-domain shows {6,5,0}). Suggests graph walks are dominated by shared scaffolding; filter-specific IDs are masked in these tiny profiles.
- Next steps: design probes with stronger anchors or use improved decoder/anchor mapping from probe-op-structure once literal bindings surface.

## Decoder and anchor improvements

- Decoder/anchor improvements now bind anchors to nodes in simple probes (via probe-op-structure), but those nodes still carry generic field2 values (global-name/local-name/path). Filter-specific IDs remain masked; need richer tag decoding and anchor-strong probes to isolate them.
- `harvest_field2.py` now threads anchor hits (when present in probe-op-structure outputs) into `out/field2_inventory.json`; system profiles carry anchor hits, probe profiles remain anchor-empty.

## New shared artifacts

- New shared artifacts unblocking deeper mapping: tag layouts published at `book/graph/mappings/tag_layouts/tag_layouts.json` and anchor → filter map at `book/graph/mappings/anchors/anchor_filter_map.json`. Use these to reinterpret anchor-bearing nodes and rerun `harvest_field2.py` for clearer filter IDs.

## Characterization updates

- Reclassified flow-divert payload 2560 as characterized (triple-only, tag0/u16_role=filter_vocab_id, literal `com.apple.flow-divert`); `unknown_focus.py` now skips it via `CHARACTERIZED_FIELD2`, and `unknown_nodes.json` refreshed.

## Kernel evaluator location (x86_64 KC)

- Located the kernel evaluator in the sandbox fileset: `FUN_ffffff8002d8547a` in `com.apple.security.sandbox` (`vmaddr 0xffffff8002d70000`, fileoff `0x02c68000`, text span `0xffffff8002d71208–0xffffff8002da9f7f`). It drives the opcode switch and calls helper readers `FUN_ffffff8002d87d4a`, `FUN_ffffff8002d87d8f`, `FUN_ffffff8002d8809a`, `FUN_ffffff8002d8907f` to load edges/`field2`. High-level decompile shows `field2` forwarded directly from `FUN_2d87d4a`; any hi-bit/lo-bit handling likely lives inside these helpers.
- Tooling state: `objdump`/`llvm-objdump` on the KC ignored the fileset entry; byte-slicing by fileoff produced “truncated/malformed object.” Need to extract the sandbox fileset (`kmutil emit-macho` or custom unwrapping) to disassemble helper functions and search for `tbz`/`tbnz`/`ubfx`/`and` masks on the payload register.
- Follow-up disassembly (fileset carve):
  - Parsed LC_FILESET_ENTRY to get the sandbox slice (fileoff `0x2c70000`, size `503808`), carved it, and locally fixed load-command file offsets/symtab to enable disassembly (`/tmp/sandbox_kext_fixed.bin`).
  - `FUN_ffffff8002d87d4a`: bounds-checks and `movzwl` a u16 from the profile byte array into a caller-provided pointer; no masks/bit-tests.
  - `FUN_ffffff8002d87d8f`/`FUN_ffffff8002d8809a`: wrappers around `2d87d4a` that scale/advance pointers; still no masking or `test/and` on the loaded u16.
  - No `testw $0x4000`/`and $0x3fff`/`ubfx`-style operations observed in these helpers or nearby snippets; suggests `field2` is consumed raw in this x86_64 KC. Need to repeat on the arm64e fileset (Apple Silicon target) to confirm the same behavior.
- Arm64e follow-up attempt: `kmutil emit-macho --arch arm64e` still produced an x86_64 KC (`cputype` 16777223), and the carved sandbox slice shows x86_64 headers. No arm64e slice available in this BootKC dump, so the helper scan currently only covers the x86_64 view.

## Inventory refresh after shared artifacts

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
  - Full-program with masks 0x3fff/0x4000/0xc000/0x00ff/0xff00: no hits. Output at `book/dumps/ghidra/out/14.4.1-23E224/kernel-field2-mask-scan/mask_scan.json`.
- Ran `kernel_imm_search` on key field2 constants across the full KC: 0xa00 (flow-divert 2560), 0x4114 (bsd tail hi-bit), and 0x2a00 (airlock high). All returned zero hits. Outputs under `book/dumps/ghidra/out/14.4.1-23E224/kernel-imm-search/`. These negatives suggest the constants are not present as plain immediates; evaluator likely derives flags via other arithmetic or indirect tables.

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

### Headless helper hunt (arm64e sandbox kext)

- Added `book/api/ghidra/scripts/find_field2_evaluator.py` and ran it headlessly against the extracted sandbox kext (`/tmp/sandbox_arm64e/com.apple.security.sandbox`) via project `sandbox_field2_sbx`.
- Output at `book/dumps/ghidra/out/14.4.1-23E224/find-field2-evaluator/field2_evaluator.json`: ~60k instructions, 897 functions. Heuristic picked `__read24` at `fffffe000b410ee4` (loads a halfword + byte with bounds checks) as the smallest widely-called ldrb+ldrh helper; callers include `_eval` at `fffffe000b40d698`, `_populate_syscall_mask`, and `_check_syscall_mask_composable`. The dumped helper/evaluator disasm lives in `helper.txt` / `evaluator.txt` alongside the JSON.
- Caveat: this heuristic is still generic; `__read24` is not yet confirmed as the field2 reader. `_eval` remains the evaluator candidate and should be dumped/inspected directly to confirm field2 handling.

### 2026-02-12 follow-up (arm64e helper + new probes)

- Refined the headless helper hunt (`book/api/ghidra/scripts/find_field2_evaluator.py`): the stricter filter now lands on `__read16` at `fffffe000b40fa1c` as the small u16 reader. Disasm in `book/dumps/ghidra/out/14.4.1-23E224/find-field2-evaluator/helper.txt` shows bounds checks and a plain `ldrh/strh`; no bit tests or masks on the payload. The script also auto-dumps `_eval` to `eval.txt`.
- `_eval` dump (`fffffe000b40d698`) shows masking with `0xffffff`, `0x7fffff`, `0x7f`, and bit-test on bit 0x17, but no `0x3fff`/`0x4000` masks. `rg` over `eval.txt` finds no 0x3fff/0x4000 immediates. `__read16` callers are mostly mask/populate helpers (`_populate_syscall_mask`, `_check_syscall_mask_composable`, `_match_network`, etc.); `__read24` remains used in `_eval` for other payloads.
- Added probes:
  - `sb/bsd_ops_default_file.sb` (default/file* cluster with simple path literals).
  - `sb/airlock_system_fcntl.sb` (system-fcntl with `fcntl-command` filters).
  Compiled via `python -m book.api.profile compile ... --out sb/build/...`.
- Refreshed `harvest_field2.py` and `unknown_focus.py` outputs. Highlights:
  - `airlock_system_fcntl` surfaces a new hi-bit sentinel `field2=0xffff` (hi=0xc000, lo=0x3fff) on tag 1, no literals; otherwise low path/socket IDs.
  - `bsd_ops_default_file` mirrors `sample` with low path/socket IDs and the existing sentinel 3584; no high bsd tail values surfaced.
  - System profiles unchanged: bsd 16660 hi=0x4000 still reachable from ops 0–27; other bsd highs op-empty. Airlock unknowns still hang off op 162. Flow-divert 2560 remains only in the triple-socket probes (v4/v7/v_net_require_all_domain_type_proto) and op-empty.
  - Updated artifacts: `out/field2_inventory.json`, `out/unknown_nodes.json`, Ghidra outputs under `book/dumps/ghidra/out/14.4.1-23E224/find-field2-evaluator/`.

## Kernel helper hunt (arm64e targets)

- Summarized unknown nodes from `out/unknown_nodes.json`:
  - `bsd`: 16660 (`hi=0x4000`, `lo=0x114`) on tag 0 with `fan_in=33`, `fan_out=1`, reachable from ops 0–27; other highs 170/174/115/109 on tag 26 with `fan_out=1`, `fan_in=0`, op-empty.
  - `airlock`: highs 165/166/10752 on tags 166/1/0; op reach concentrated on op 162 (`system-fcntl`); new sentinel 0xffff in `airlock_system_fcntl` (tag 1, hi=0xc000).
  - `flow-divert`: 2560 only in mixed require-all (domain+type+protocol) probes, tag 0, fan_in=0, fan_out=2→node0, op-empty.
  - `sample` and probe bsd/airlock clones: sentinel 3584 on tag 0, fan_out=2→node0, op-empty.
- Parsed `field2_evaluator.json`: `__read16` callers include `_populate_syscall_mask`, `_variables_populate`, `_match_network`, `_check_syscall_mask_composable`, `_iterate_sandbox_state_flags`, `_re_cache_init`, `_match_integer_object`, `___collection_init_block_invoke`, `_match_pattern`, `__readstr`, `__readaddr`. These are the current places to hunt for comparisons/table lookups on `filter_arg_raw`.
- `rg` across `eval.txt` still shows no immediates for the unknown constants (0xa00/0x4114/0x2a00/0xffff/0xe00), reinforcing that the helper/evaluator pass the u16 through unmasked. Next kernel step: open these caller functions in Ghidra and inspect how the loaded value is consumed (direct compare vs table index).

## Caller dumps attempt (headless, initial)

- Tried to dump `__read16` callers directly from the carved sandbox kext using `llvm-objdump` on slices around their VM addresses. Both Mach-O and raw-binary modes failed: the extracted binary still trips `truncated or malformed object` for whole-file disassembly, and per-slice disasm reports “is not an object file.”
- Approach to unblock: lean on Ghidra (existing `sandbox_field2_sbx` project) to emit disassembly for the caller set. Next run should add a simple headless script to print instructions for the known callers (`_populate_syscall_mask`, `_variables_populate`, `_match_network`, `_check_syscall_mask_composable`, `_iterate_sandbox_state_flags`, `_re_cache_init`, `_match_integer_object`, `___collection_init_block_invoke`, `_match_pattern`, `__readstr`, `__readaddr`) and capture how the `__read16` return register is used (compare vs table index). Whole-file objdump is not viable on this carved binary without repairing headers further.

## Headless Ghidra caller dump attempt

- Attempted to run a headless Ghidra script (`dump_read16_callers.py`) against project `sandbox_field2_sbx` to dump the caller set. Command failed early with:
  - `/Users/achyland/Library/ghidra/ghidra_11.4.2_PUBLIC/java_home.save (Operation not permitted)`
  - `ERROR: Unable to prompt user for JDK path, no TTY detected.`
- This is the familiar “JDK prompt in headless” issue noted in `ghidra_setup.md`. Resolution: rerun with `JAVA_HOME` and `-vmPath` set, and `HOME`/`GHIDRA_USER_HOME` pointing to the repo-local sandbox (`book/dumps/ghidra/user`). The existing scaffold does this; the ad hoc call here lacked the env. Next action: rerun the caller dump via `book/api/ghidra/run_task.py` or with explicit env (`JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home`, `HOME=.../book/dumps/ghidra/user`, `GHIDRA_USER_HOME=.../book/dumps/ghidra/user`, `-vmPath $JAVA_HOME/bin/java`), then collect the disassembly into `book/dumps/ghidra/out/14.4.1-23E224/find-field2-evaluator/callers/read16_callers.txt`.

## Headless retry still blocked

- Retried the caller dump with explicit env (`JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home`, `HOME`/`GHIDRA_USER_HOME` to `book/dumps/ghidra/user`, `-vmPath` set). The headless run still failed with the same prompt errors (`java_home.save` EPERM / “Unable to prompt user for JDK path, no TTY”).
- This matches the `ghidra_setup.md` caution: ad hoc headless invocations that don’t set `JAVA_TOOL_OPTIONS=-Duser.home=<repo>/book/dumps/ghidra/user` or don’t run through the scaffold continue to hit the prompt.
- Next possible solutions:
  - Use the repo’s `book/api/ghidra/run_task.py` (which wires env and `--java-home/-vmPath`) to invoke a small script that dumps the caller set, instead of hand-rolling `analyzeHeadless`.
  - Alternatively, set `JAVA_TOOL_OPTIONS=-Duser.home=$PWD/book/dumps/ghidra/user` alongside `JAVA_HOME`/`-vmPath` before calling headless directly.
  - If headless continues to balk, fall back to an interactive Ghidra session to export caller disassembly, then park the dumps under `book/dumps/ghidra/out/14.4.1-23E224/find-field2-evaluator/callers/`.

## Headless caller dump via settingsdir override

- Applied the settingsdir guidance: seeded a repo-local settings dir (`.ghidra-user/ghidra/ghidra_11.4.2_PUBLIC/java_home.save`) and invoked `analyzeHeadless` with `JAVA_TOOL_OPTIONS="-Dapplication.settingsdir=$PWD/.ghidra-user -Duser.home=$PWD/book/dumps/ghidra/user"` plus HOME/GHIDRA_USER_HOME pointing to `book/dumps/ghidra/user`. Dropped unsupported flags (`-vmPath`, `-logFile`).
- Headless run succeeded; dumped caller disassembly to `book/dumps/ghidra/out/14.4.1-23E224/find-field2-evaluator/read16_callers.txt` using a Jython script (`/tmp/dump_read16_callers.py`) that iterates functions by name.
- Quick scan findings (no deep analysis yet):
  - Callers (`__readaddr`, `__readstr`, `_check_syscall_mask_composable`, `_iterate_sandbox_state_flags`, etc.) call `__read16` early and then perform range/size checks; several mask the payload with `#0xffff` (e.g., `and x?, #0xffff`, `tst w?, #0xffff`), but no immediates matching our unknowns (0xa00/0x4114/0x2a00/0xffff/0xe00) appear.
  - No direct comparisons against the high field2 constants in these snippets; paths mostly dispatch to error/log helpers (`...f78c`) on failure.
- Next: mine `read16_callers.txt` for exact mask patterns and, if useful, extend the script to capture basic-block context around the `0xffff` tests. The new env wiring should keep headless stable for further passes.

### Mask contexts pulled from `read16_callers.txt`

- Parsed `read16_callers.txt` for `#0xffff` uses; hits clustered in four functions:
  - `_check_syscall_mask_composable`: multiple `tst w24,#0xffff` / `and x8,x24,#0xffff` and `and w9,w24,#0xffff` sequences guarding control flow before further helper calls; no high-constant compares.
  - `_iterate_sandbox_state_flags`: `tst w8,#0xffff` followed by `and x8,x8,#0xffff` and `and w2,w22,#0xffff`; used as bounds/mask checks, no high constants.
  - `_match_network`: single `tst w10,#0xffff` gate after a protocol/domain compare.
  - `_variables_populate`: `tst w9,#0xffff` then `and x9,x9,#0xffff` prior to address arithmetic; again just masking, no high-constant compares.
- No occurrences of 0xa00/0x4114/0x2a00/0xe00/0xffff as immediates in these callers. Suggests `filter_arg_raw` is masked to 16 bits in places but not compared against our unknown constants here. Next refinement would be to correlate these mask sites with the node fields they read (e.g., which node/tag they’re decoding) or widen context to nearby table lookups.

## New probe variants (field2 sweeps)

## Closure posture (structural only)

- Slot is treated as a raw u16 (`filter_arg_raw`) whose meaning is tag-structured and tied to the host filter vocabulary; beyond in-vocab vs out-of-vocab, semantics remain closed as a negative result (SBPL toggles + kernel reader hunts exhausted).
- Roles are now explicit: tag layouts stay in `tag_layouts.json`, and per-tag u16 roles are captured in `tag_u16_roles.json` (filter_vocab_id/arg_u16/none/meta). Decoder stays permissive and table-driven; validation/guardrails on canonical corpora enforce that encountered tags have explicit layouts/roles and that out-of-vocab values are inventoried, not interpreted.
- Unknown/high values are parked as bounded opaque tokens on this host; no further semantic inference is attempted unless a new, apply-able specimen plus runtime harness is named to reopen the question.

- Added `net_require_all_domain_type_proto_udp.sb` to mirror the TCP require-all matrix with UDP (AF_INET + SOCK_DGRAM + IPPROTO_UDP). Compilation + harvest show the same `field2=2560` flow-divert tag0 node as the TCP variant; no new high IDs or anchors surfaced.
- Added `airlock_system_fcntl_matrix.sb` (fcntl-command sweep 0–3) to probe whether command payloads drive the 0xffff/0xa5/0xa6 highs. Decode/harvest shows only low scaffolding filters (ipc-posix-name/file-mode) and no unknown/high `field2` values.
- Added `right_and_preference_names.sb` (right-name/preference-domain literals) to see if tag26/27 highs map to literal arguments. Decode shows only path/name scaffolding; no high/unknown `field2` values and no tag26/27 payloads beyond vocab IDs.
- Reran `harvest_field2.py` and `unknown_focus.py` to fold in the new profiles. Unknowns remain limited to the existing clusters: flow-divert `field2=2560` on tag0 nodes with edges →0, bsd tail `field2=0x4114` and tag26 payloads, airlock highs {165,166,0x2a00}, and the probe-only 0xffff sentinel on `airlock_system_fcntl`.
- Added guardrail `book/tests/planes/graph/test_field2_unknowns.py` to pin the current unknown/high `field2` set; adjust `EXPECTED_UNKNOWN_RAW` deliberately if future probes surface new unknowns.

- Decoder framing update: the decoder now selects an 8-byte node record framing for this world based on op-table alignment evidence, and `profile_ingestion.slice_sections` now uses the same lower-bound witness to avoid truncating the node region.
- Reran `harvest_field2.py` and `unknown_focus.py` under the updated framing and regenerated `out/field2_inventory.json` and `out/unknown_nodes.json`.
- `sys:bsd` “unknown/high” payloads (prior bsd tail `0x4114` and tag26 highs 170/174/115/109) disappear under the stride=8 framing; they were decode artifacts from the earlier stride=12 approximation.
- `unknown_focus.py` now scopes `unknown_nodes.json` to nodes with `u16_role=filter_vocab_id` to avoid inflating the unknown set with tags whose u16[2] slot is treated as `arg_u16` on this host baseline.
- Current out-of-vocab field2 set (excluding the characterized flow-divert 2560): `{165, 256, 1281, 2816, 3584, 12096, 49171}`.

## Retire flow-divert 2816 from the unknown census

- Treated `filter_arg_raw=2816` (`0x0b00`) as characterized (triple-only alongside `2560`) using the same flow-divert matrix witness, and excluded it from `unknown_focus.py`’s unknown census (`CHARACTERIZED_FIELD2`).
- Reran `unknown_focus.py` and regenerated `out/unknown_nodes.json`; current unknown/high set (scoped to `u16_role=filter_vocab_id` and excluding 2560/2816) is now `{165, 256, 1281, 3584, 12096, 49171}`.
