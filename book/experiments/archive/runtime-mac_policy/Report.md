# runtime-mac_policy – Research Report

## Purpose
Trace sandbox/mac_policy registration at runtime and capture live `mac_policy_conf`/`mac_policy_ops` evidence (call sites, arguments, and resolved pointers). This is not part of the static “book world” for `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`; it uses a separate runtime-only world to look for evidence the static world cannot see. On the current runtime host no registration events were observed after trace attach.

## Baseline & scope
- Static reference: `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5` (Apple Silicon, SIP on) stays the comparison point for vocab/op-table IR. Runtime observations come from separately tagged runtime worlds and must carry their own host metadata.
- Current runtime host: VM tagged `runtime-mac-policy-dev` running macOS 14.6.1 (23G93), arm64, SIP disabled to allow `fbt`. This host is intentionally separate from the static baseline.
- Inputs: runtime tracing/probing of the kernel/mac_policy layer; static mappings and CARTON stay read-only references.
- Out of scope: cross-version generalizations or any claim not grounded in the eventual runtime world’s behavior.

## Model (public anchor)
- `mac_policy_register(struct mac_policy_conf *mpc, mac_policy_handle_t *handlep, void *xd)` registers a MACF policy with the kernel.
- `struct mac_policy_conf` fields: `mpc_name`, `mpc_fullname`, `mpc_labelnames`, `mpc_labelname_count` (u32 + padding), `mpc_ops`, `mpc_loadtime_flags`, `mpc_field_off` (or label slot), `mpc_runtime_flags`, plus optional list/data pointers.
- Expected runtime signature: call sites should pass a concrete `mpc` pointer, a handle out pointer, and a context pointer; `mpc_ops` should point to the policy’s hook table.

## Evidence goals
- Registration events (call-level):
  - Target function identity: address treated as `mac_policy_register` (or wrapper) plus binary/segment classification.
  - Argument values at entry: `mpc` (first arg), `handlep` (second), `xd` (third).
  - Call-site context: caller PC, caller classification (kernel text, `com.apple.security.sandbox`, other MACF consumer).
  - Region classification for `mpc`: kernel text/data, sandbox kext text/data, or other.
- `mac_policy_conf` / `mpc_ops` snapshot:
  - Raw read of 10–12 slots covering the public layout; decoded view into name/fullname/labelnames/labelname_count/ops/loadtime_flags/field/runtime_flags/optionals.
  - Best-effort string decode for `mpc_name`/`mpc_fullname` (bounded ASCII), classified (sandbox/seatbelt, AppleMatch, other).
  - `mpc_ops` read: raw pointer plus bounded sample of entries (e.g., first 64–128 words) with target address and image/segment for non-NULL entries.
- Alignment hooks:
  - Map observed code pointers to Mach-O image + segment + offset to tie runtime addresses back to static blobs.
  - Maintain a partial index of static op-table entries (representative operations) for comparison.

## Plan (skeleton)
1) Identify registration targets (two conceptual tracks):
   - Kernel/seatbelt track: locate the core MACF registration function (real `mac_policy_register` or its direct wrapper) to observe global MACF policy population.
   - Sandbox-specific track: locate the call site that registers the sandbox policy (sandbox kext or bootstrap path).
   - Schema must represent events from either track.
2) Capture call-level evidence:
   - Probe the chosen target(s); log target identity, caller PC/classification, and argument registers (`mpc`, `handlep`, `xd`).
   - Classify `mpc` region (kernel text/data, sandbox kext, other).
3) Capture memory snapshots:
   - Read `mac_policy_conf` slots (raw + decoded) and a bounded slice of `mpc_ops` entries; decode strings when possible and classify them.
   - Serialize into `runtime_mac_policy_registration.json` with per-event fields for call info, struct snapshot, ops sample, and region mappings.
4) Align to static IR (asymmetric, one-way):
   - For each `mpc_ops`, map entry pointers to image/segment/offset and compare a representative subset of indices against `book/graph/mappings/op_table/op_table.json`.
   - Allow outcomes: shape-compatible (weak/strong alignment) or shape-incompatible (suggesting per-policy or alternative tables). No reconstruction or overwrite of static op-table mapping.

## Evidence & artifacts
- Schema: `runtime_mac_policy_registration.schema.json`.
- Tooling: `capture.py` (dynamic DTrace wrapper) and `normalize.py` (raw → schema JSON); sanity-checked by experiment-local `book/experiments/runtime-mac_policy/test_normalize.py` (not run by `make -C book test`).
- Runtime world metadata: `book/world/runtime-mac-policy-dev/world.json` (macOS 14.6.1, build 23G93, SIP disabled; runtime-only host).
- Captures:
  - `out/raw/fbt_smoketest.log` and `out/fbt_smoketest.json` — single `fbt:mach_kernel:vnode_put:entry` event (pipeline proof).
  - `out/raw/mac_policy_register_min.log` and `out/mac_policy_register_min.json` — no events (ran with `/bin/ls /`).
  - `out/raw/mac_policy_register_sleep.log` and `out/mac_policy_register_sleep.json` — no events (5s dwell).
- Static references: untouched; alignment/struct fields remain empty because no `mac_policy_register` events fired post-attach.

## Proposed JSON schema (`runtime_mac_policy_registration.json`)
Top-level object:
- `world_id`: runtime world identifier.
- `host`: metadata (os_build, kernel_version, boot_mode/protections, kc_hash, sandbox_kext_hash, tracing_config).
- `events`: array of registration events.
- `static_reference`: optional pointers to static IR used for alignment (e.g., op_table_mapping_sha, vocab_sha).

Event object fields:
- `target`: `{ "addr": "0x...", "image": "...", "segment": "...", "role": "mac_policy_register|wrapper" }`
- `caller`: `{ "pc": "0x...", "image": "...", "segment": "...", "classification": "kernel|sandbox_kext|other" }`
- `args`: `{ "mpc": "0x...", "handlep": "0x...", "xd": "0x..." }`
- `mpc_region`: `"kernel_text|kernel_data|sandbox_text|sandbox_data|other"`
- `mpc_snapshot`: raw and decoded struct:
  - `raw_slots`: `[ "0x...", ... ]` (10–12 qwords covering the template)
  - `decoded`: `{ "name": "0x...", "fullname": "0x...", "labelnames": "0x...", "labelname_count": <int>, "ops": "0x...", "loadtime_flags": "0x...", "field_or_label_slot": "0x...", "runtime_flags": "0x...", "extra": ["0x...", "0x..."] }`
  - `strings`: `{ "name": "Sandbox|AppleMatch|...", "fullname": "..." }` (null if not readable)
- `mpc_ops`: `{ "ptr": "0x...", "entries": [ { "index": <int>, "addr": "0x...", "image": "...", "segment": "..." }, ... ] }` (bounded sample, e.g., first 64–128 entries; omit NULLs)
- `alignment`: comparison results against static op-table:
  - `status`: `"strong|weak|incompatible|unknown"`
  - `matched_indices`: `[<int>, ...]`
  - `notes`: freeform string for discrepancies or per-policy hints.

## Status
- Runtime host prepared: SIP disabled (`csrutil status` → disabled); `fbt` probes usable. Host metadata recorded in `book/world/runtime-mac-policy-dev/world.json`.
- Pipeline proven with `fbt`: `fbt:mach_kernel:vnode_put:entry` probe produced one EVENT (`out/raw/fbt_smoketest.log`, `out/fbt_smoketest.json`).
- Target discovery: `fbt:mach_kernel:mac_policy_register:{entry,return}` is present.
- Outcome: no `mac_policy_register` events observed after attach (both `/bin/ls /` and 5s dwell captures produced zero events). Conclusion: built-in MACF policies, including sandbox, register before DTrace can attach on this host and no dynamic MACF policies register later.
- Current status: `design-only / blocked by timing (registration pre-attach); pipeline and schema retained for future runtime hosts`. Static references remain untouched; struct/ops alignment unpopulated.

## Conclusion
On this runtime host (macOS 14.6.1, SIP disabled), DTrace `fbt` works and the capture/normalize pipeline is functional, but `mac_policy_register` never fires after attachment. The experiment is parked as design-only for this host; the tooling and schema remain for future runtime worlds or alternate instrumentation paths.
