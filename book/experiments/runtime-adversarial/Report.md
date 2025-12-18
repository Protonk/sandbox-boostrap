# Runtime Adversarial Suite – Research Report

## Purpose
Deliberately stress static↔runtime alignment for this host using adversarial SBPL profiles. This suite covers three families:
- Structural filesystem variants (file-read*/file-write*).
- VFS edge cases (`/tmp` vs `/private/tmp`).
- Non-filesystem ops (`mach-lookup` and `network-outbound`).
Outputs: expected/runtime matrices, mismatch summaries, and impact hooks to downgrade bedrock claims if mismatches appear.

## Baseline & scope
- World: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5` (`book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json`).
- Harness: `book.api.runtime_harness.runner.run_expected_matrix` + runtime-checks shims; compile/decode via `book.api.profile_tools` and `book.api.profile_tools.decoder`.
- Profiles: `struct_flat`, `struct_nested` (structural variants); `path_edges` (path/literal edge stress); `mach_simple_allow`, `mach_simple_variants`, `mach_local_literal`, `mach_local_regex` (mach-lookup variants); `net_outbound_allow`, `net_outbound_deny` (network-outbound variants). Custom SBPL only; no platform blobs.
- Outputs live in `sb/`, `sb/build/`, and `out/`.

## Families and findings

### Structural variants (struct_flat / struct_nested)
- Static intent: distinguish allowed vs denied paths under a simple subpath policy rooted at `/tmp/runtime-adv/struct/ok`.
- Runtime: read/write probes match static expectations for both `struct_flat` and `struct_nested`; structural differences do not change behavior.
- Conclusion: structural layout differences in these profiles do not affect allow/deny semantics for file-read*/file-write* in this scenario.

### VFS edge cases (path_edges)
- Static intent: allow literal `/tmp/runtime-adv/edges/a` and subpath `/tmp/runtime-adv/edges/okdir/*`, deny `/private/tmp/runtime-adv/edges/a` and the `..` literal to catch traversal. Decoder predicts allows on `/tmp/...` probes via literal/subpath filters.
- Runtime: both `/tmp/...` allow probes return deny with `EPERM` (open target) despite static allow; `/private/tmp` deny and `..` deny align; write-side probes show the same pattern.
- Interpretation: mismatch attributed to VFS canonicalization (`/tmp` → `/private/tmp`) prior to PolicyGraph evaluation rather than tag/layout divergence. Treated as out-of-scope for static IR; captured in `impact_map.json` with `out_of_scope:VFS_canonicalization` and no downgrade to bedrock mappings.

### Mach families (mach_simple_* / mach_local_*)
- Static intent: allow `mach-lookup` for `com.apple.cfprefsd.agent` only; profiles use literal vs regex and global-name vs local-name encodings, but aim for the same allow/deny surface (explicit deny on a bogus service).
- Runtime: with baseline allows added for process exec and system reads, all mach profiles allow the target service and deny the bogus one; no mismatches recorded. `impact_map.json` marks these expectation_ids as reinforcing the mach-lookup vocab/op-table assumptions (op ID 96).
- Conclusion: mach runtime coverage is `ok` for this allow/deny pair; current tag/layout + op-table decoding for mach filters aligns with kernel behavior across literal/regex and global/local-name variants.

### Network family (net_outbound_allow / net_outbound_deny)
- Static intent: exercise `network-outbound` under deny-default profiles where the only policy difference is the presence/absence of an allow rule for outbound network.
- Runtime: early attempts that sandboxed Python hit startup/file-access noise; the final design uses `/usr/bin/nc` as the sandboxed client with startup shims and `system-socket`. Under that design, allow/deny profiles cleanly split on `network-outbound` (see “Network-outbound runtime confirmation” below).

## Evidence & artifacts
- SBPL sources: `book/experiments/runtime-adversarial/sb/*.sb`.
- Expected/runtime outputs: `book/experiments/runtime-adversarial/out/{expected_matrix.json,runtime_results.json,mismatch_summary.json,impact_map.json}`.
- Mapping stub: `book/graph/mappings/runtime/adversarial_summary.json` (world-level counts).
- Guardrails: `book/tests/test_runtime_adversarial.py`, `book/tests/test_network_outbound_guardrail.py`, plus dyld slice manifest/checker `book/graph/mappings/dyld-libs/{manifest.json,check_manifest.py}` enforced by `book/tests/test_dyld_libs_manifest.py`.
- Runtime-backed ops: `book/graph/mappings/vocab/ops_coverage.json` marks `file-read*`, `file-write*`, `mach-lookup`, and `network-outbound` as having runtime evidence via runtime-checks and runtime-adversarial families; use it to decide when new probes are needed for other ops.

## Claims and limits
- Covered ops/shapes: adversarial probes cover file-read*/file-write* (bucket-4/bucket-5 filesystem profiles and structural/metafilter variants), `mach-lookup` (global-name and local-name, literal and regex, simple vs nested forms), and `network-outbound` (loopback TCP via nc under deny-default + startup shims).
- Static↔runtime alignment: for these ops and shapes, decoded PolicyGraph IR (vocab, tag layouts where used, op-tables, and graphs) matches kernel behavior even under deliberately adversarial constructions; structural variants, mach families, and the canonical network scenario all agree with static expectations.
- Bounded mismatch: the only systematic divergence observed is the `/tmp` → `/private/tmp` behavior in `path_edges`, explicitly classified as VFS canonicalization outside the PolicyGraph model and recorded in `impact_map.json` as out-of-scope, not as a decoder bug.
- Scope of claims: this justifies treating the static PolicyGraph IR as a bedrock stand-in for kernel enforcement for the covered ops on this host, but it is not a universal theorem over all 196 operations; for ops without `runtime_evidence: true` in `ops_coverage.json`, agents should design new probes or treat claims as more tentative.
- Routing: when you need empirically grounded behavior for file-read*, file-write*, mach-lookup, or network-outbound on this world, treat the existing IR plus `runtime-adversarial` outputs (`expected_matrix.json`, `runtime_results.json`, `mismatch_summary.json`, `impact_map.json`) as canonical; when stepping outside those ops, consult `ops_coverage.json` and extend `runtime-adversarial` first.

## Network-outbound runtime confirmation
This family targets the `network-outbound` operation to confirm mapped behavior on this host via a clean runtime allow/deny split. Early attempts that sandboxed Python hit startup/file-access noise; the final design deliberately avoids sandboxing Python and pins the client to `/usr/bin/nc`.

### Canonical scenario
- **Host**: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5` (this scenario is scoped to this world).
- **Client**: `/usr/bin/nc -z -w 2`.
- **Profiles**: deny default plus startup shims (`iokit-open`, `mach* sysctl-read`, `file-ioctl`, `file-read-metadata`, `file-read-data` over `/`, `/System`, `/usr`, `/Library`, `/private`, `/dev`), `system-socket`, and `process-exec` pinned to `/usr/bin/nc`.
  - `sb/net_outbound_allow.sb`: includes `allow network-outbound …`.
  - `sb/net_outbound_deny.sb`: identical except it omits `network-outbound`.
- **Topology**: two loopback targets (as emitted in `out/expected_matrix.json`, e.g., `127.0.0.1:<port1>` and `127.0.0.1:<port2>`). The harness spins up listeners on both and runs `/usr/bin/nc` under each profile against both targets.

### Manual control (sandbox-exec)
Before refactoring the harness, a bespoke SBPL under `sandbox-exec -f … /usr/bin/nc 127.0.0.1 <port>` with deny-default, startup shims, `system-socket`, and a localhost `network-outbound` rule showed: allow profile → successful TCP connect; deny profile → denied connect. The harness design mirrors this control, proving Sonoma + Seatbelt + `network-outbound` + `nc` works when Python is not sandboxed.

### Results and propagation
- Runtime behavior: 4 loopback probes (two targets × allow/deny). All 4 match expectations: allow profile allows both targets; deny profile denies both.
- IR updates:
  - `book/graph/mappings/runtime/runtime_signatures.json` now includes `adv:net_outbound_allow` and `adv:net_outbound_deny` entries with per-probe results.
  - `book/graph/mappings/vocab/ops_coverage.json` marks `network-outbound` `runtime_evidence: true` (alongside file-read*, file-write*, mach-lookup).
  - CARTON coverage and indices regenerated (`book/graph/mappings/carton/operation_coverage.json`, `operation_index.json`, `profile_layer_index.json`) so `network-outbound` lists its runtime signatures.
  - `book/experiments/op-coverage-and-runtime-signatures/out/op_runtime_summary.json` reports `network-outbound` 4/4 matches.

### Guardrail test
- Structural: `book/tests/test_network_outbound_guardrail.py` loads `sb/net_outbound_allow.sb` and `sb/net_outbound_deny.sb` and asserts they are identical except for the `network-outbound` rule.
- Behavioral: the same test checks `adv:net_outbound_allow*` probes all yield allow and `adv:net_outbound_deny*` probes all yield deny in `out/runtime_results.json`.
- Intent: prevents reintroducing sandboxed Python or profile shape drift that would blur the `network-outbound` decision between harness noise and PolicyGraph behavior.

### Status and adjacent work
- `network-outbound` is confirmed on this world by runtime via the canonical scenario and marked runtime-backed in coverage and CARTON.
- Planned but non-blocking: add a small variant (alternate port or IPv6 loopback) using the same client/profiles; add a “negative harness” profile (remove `system-socket`) expected to fail as a harness/startup error rather than a policy decision.
- Remaining runtime divergences: `/tmp`→`/private/tmp` VFS canonicalization in filesystem probes; to be addressed via a focused runtime-adversarial family and guardrails.

## Next steps
- Extend network coverage with a small variant (alternate port or IPv6 loopback) using the same client/profiles; add a “negative harness” profile (remove `system-socket`) expected to fail as a harness/startup error rather than a policy decision.
- Design a focused VFS canonicalization family for `/tmp` → `/private/tmp` with its own guardrails so path_edges behavior is explicitly modeled and bounded.
- Extend families (header/format toggles, field2/tag ambiguity, additional non-filesystem ops) once current cases are stable; wire additional validation selectors if promotion to shared runtime mappings is desired.
