# Report – op-coverage-and-runtime-signatures

## Purpose

This suite asks: for this world (`world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`), how well do operation vocabulary entries, profile coverage, and runtime outcomes line up for the operations we have actually exercised? Today it reuses the `runtime-adversarial` harness to provide runtime-backed evidence for `file-read*` and `mach-lookup` and summarizes that evidence per operation.

The goal is that someone can look at a single JSON file and see, per operation:
- how many probes we ran,
- how often runtime behavior matched static expectations, and
- where known mismatches live and how they are interpreted.

Future work can extend this pattern to more operations and tie it directly into `ops_coverage.json` and `runtime_signatures.json`.

## Baseline & scope

- World: `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
- Harness: `book/experiments/runtime-adversarial/run_adversarial.py` plus `sandbox_runner` / `sandbox_reader` from `book/experiments/runtime-checks/`.
- Profiles: adversarial families that already exercise `file-read*` and `mach-lookup`:
  - `adv:struct_flat`, `adv:struct_nested`, `adv:path_edges` (filesystem).
  - `adv:mach_simple_allow`, `adv:mach_simple_variants`, `adv:mach_local_literal`, `adv:mach_local_regex` (mach).
- Inputs: expected/runtime matrices in `book/experiments/runtime-adversarial/out/{expected_matrix.json,runtime_results.json}`.
- Local copies: `harvest_runtime_artifacts.py` copies `runtime_results.json`, `expected_matrix.json`, `mismatch_summary.json`, and `impact_map.json` into this suite’s `out/` for downstream summarization.
- Outputs (this suite): aggregated per-op summary in `book/experiments/op-coverage-and-runtime-signatures/out/op_runtime_summary.json`.

Scope today: `file-read*`, `file-write*`, `mach-lookup`, and `network-outbound`, matching the current adversarial probe families.

## Status update (permissive host)

The latest refresh ran under the permissive host context (`--yolo`), so apply-stage EPERM is cleared for adversarial probes. `out/op_runtime_summary.json` now records decision-stage outcomes again, with only the expected `path_edges` mismatches (see `book/experiments/vfs-canonicalization/Report.md`, mapped).

## Mechanism

1. **Run adversarial probes**
   - Command: `python book/experiments/runtime-adversarial/run_adversarial.py`.
   - This compiles SBPL profiles, runs them under `sandbox_reader`/`sandbox_runner`, and writes detailed results to `runtime_results.json` (per profile, per probe: operation, path/name, expected vs actual verdict, errno, stdout/stderr).

2. **Harvest runtime outputs locally**
   - Command: `python book/experiments/op-coverage-and-runtime-signatures/harvest_runtime_artifacts.py`.
   - Copies `runtime_results.json` (and expected/mismatch JSONs) from `runtime-adversarial/out/` into this suite’s `out/` to make the per-op summary independent of the sibling directory.

3. **Summarize by operation**
   - Command: `python book/experiments/op-coverage-and-runtime-signatures/summarize_from_adversarial.py`.
   - This script reads the local `out/runtime_results.json`, groups probes by the `"operation"` field, and counts for each op:
     - total probes,
     - how many matched expectations (`expected == actual` and `match: true`),
     - how many mismatched, with a small list of example probes and a richer `mismatch_details` block.
   - Output: `out/op_runtime_summary.json`, a compact “per-op runtime scorecard” for the covered ops.

No new probes are defined here yet; the suite is an evidence-aggregation and interpretation layer over the existing adversarial runs.

## Current results

From the latest run described in `Notes.md`:

- `file-read*`
  - 12 probes.
  - 10 probes match expectations; 2 are mismatches.
  - Both mismatches come from the `adv:path_edges` family and have:
    - expected `allow` on `/tmp/...` paths,
    - actual `deny` with `EPERM` and `open target: Operation not permitted`,
    - consistent with `/tmp` being canonicalized to `/private/tmp` before evaluation; see `book/experiments/vfs-canonicalization/Report.md` (mapped).

- `file-write*`
  - 12 probes (mirroring the read paths via `sandbox_writer`).
  - 10 probes match expectations; 2 mismatches (`write-tmp`, `write-subpath`) mirror the read-side path_edges behavior: intended allows on `/tmp/...` become denies with `EPERM`, again consistent with `/tmp`→`/private/tmp` VFS canonicalization (see `book/experiments/vfs-canonicalization/Report.md`, mapped).

- `mach-lookup`
  - 8 probes across the mach families.
  - 8/8 probes match expectations:
    - allows on the target `com.apple.cfprefsd.agent` (global and local names),
    - denies on bogus services,
    - consistent for both literal and regex encodings and for structural variants.

- `network-outbound`
  - 4 probes (two per network profile, two loopback targets).
  - `adv:net_outbound_allow`: expected allow, observed allow on both TCP connects to harness-started loopback listeners using `/usr/bin/nc` (no Python in the sandbox).
  - `adv:net_outbound_deny`: expected deny, observed deny for both targets.
  - Interpretation: with the sandboxed client switched to `nc` and startup shims, the network allow/deny split matches expectations. Network-outbound is now runtime-backed in this harness; `ops_coverage.json` and carton coverage have been regenerated to reflect runtime evidence.

These counts and examples are reflected directly in `out/op_runtime_summary.json`.

## Network-outbound runtime confirmation

- **Operation/goal**: `network-outbound`; confirm mapped behavior on this host via a clean runtime allow/deny scenario, avoiding earlier sandboxed-Python startup noise.

### Canonical scenario
- **Host**: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5` (scoped to this world).
- **Client**: `/usr/bin/nc -z -w 2`.
- **Profiles**: deny default with startup shims (`iokit-open`, `mach* sysctl-read`, `file-ioctl`, `file-read-metadata`, `file-read-data` over `/`, `/System`, `/usr`, `/Library`, `/private`, `/dev`), `system-socket`, `process-exec` pinned to `/usr/bin/nc`; allow profile adds `allow network-outbound`, deny omits it. See `book/experiments/runtime-adversarial/sb/net_outbound_{allow,deny}.sb`.
- **Topology**: two harness-started loopback listeners (targets recorded in `book/experiments/runtime-adversarial/out/expected_matrix.json`), `/usr/bin/nc` runs under each profile against both.

### Manual control (sandbox-exec)
Before harness changes, a bespoke SBPL under `sandbox-exec -f tcp_loopback.sb /usr/bin/nc 127.0.0.1 <port>` with the same shims showed: allow profile → successful TCP connect; deny profile → denied connect. The harness mirrors this control to keep Python out of the sandboxed path and isolate the `network-outbound` decision.

### Results and propagation
- Runtime: 4 loopback probes (two targets × allow/deny); all 4 match (allow allows both; deny denies both). See `book/experiments/runtime-adversarial/out/runtime_results.json`.
- IR:
  - `book/graph/mappings/runtime/runtime_signatures.json` includes `adv:net_outbound_{allow,deny}`.
  - `book/graph/mappings/vocab/ops_coverage.json` marks `network-outbound` `runtime_evidence: true` (with file-read*, file-write*, mach-lookup).
  - CARTON coverage/index (`book/graph/mappings/carton/operation_coverage.json`, `operation_index.json`, `profile_layer_index.json`) list the network runtime signatures.
  - `out/op_runtime_summary.json` shows `network-outbound` 4/4 matches.

### Guardrail test
- `book/tests/test_network_outbound_guardrail.py` enforces:
  - Structural: allow/deny SBPLs are identical except for the `network-outbound` rule.
  - Behavioral: `adv:net_outbound_allow*` probes all allow; `adv:net_outbound_deny*` probes all deny in `runtime_results.json`.
- Intent: prevent reintroducing sandboxed Python or profile drift that would muddle the `network-outbound` decision between harness noise and PolicyGraph behavior.

### Status and adjacent work
- `network-outbound` is confirmed on this world by runtime via the canonical scenario and marked runtime-backed in coverage and CARTON.
- Planned but non-blocking: add a small variant (alternate port or IPv6 loopback) using the same client/profiles; add a “negative harness” profile (remove `system-socket`) expected to fail as a harness/startup error rather than a policy decision.
- Remaining runtime divergences: `/tmp`→`/private/tmp` VFS canonicalization in filesystem probes; see `book/experiments/vfs-canonicalization/Report.md` for the focused canonicalization family and guardrails (mapped).

## What system info and code we are using

- **System behavior**
  - The results of real `sandbox` decisions for file reads and mach lookups on this host, as captured by the adversarial suite.
- VFS handling of `/tmp` vs `/private/tmp`, visible via the `EPERM` and path patterns in the path_edges mismatches (see `book/experiments/vfs-canonicalization/Report.md`, mapped).

- **Code paths**
  - `runtime-adversarial` defines the SBPL profiles, expected matrices, and runs that produce the raw evidence.
  - `sandbox_runner` / `sandbox_reader` encapsulate how we call into the sandbox and interpret process exit, errno, and output.
  - `summarize_from_adversarial.py` is the thin glue that turns a rich per-probe dataset into per-op statistics.

Together, these give a concrete, host-specific view of “how well do static expectations for op X match runtime behavior?” for the covered ops.

## What else this suite could tell us

The existing mechanism could be extended in several useful directions:

- **More operations**
  - Adding new adversarial families for currently uncovered operations (network, additional IPC, extensions, etc.) and re-running this summarizer would produce per-op runtime evidence across a much wider slice of the vocab.

- **Runtime signatures**
  - The current summary only tracks allow/deny and match flags. If the adversarial logs (or this summarizer) were extended to include the runtime signature IDs recorded in `book/graph/mappings/runtime/runtime_signatures.json`, the suite could directly validate “op → signature” linkage, not just “op → allow/deny”.

- **Profile and layer coverage**
  - Including which profile IDs/layers were active for each probe would let us answer “which profiles exercise op O at runtime?” and cross-check expectations around system vs synthetic coverage.

## How we could vary or strengthen the experiments

- **Environment variation**
  - Running the same probes under modified tmp setups, different working directories, or container/entitlement contexts could separate harness quirks and environment effects (like `/tmp` canonicalization) from core PolicyGraph behavior.

- **Edge-case adversaries**
  - Designing additional probe cases for borderline paths, unusual mach names, or operations with ambiguous semantics would help find places where static IR and runtime behavior diverge.

- **Validation integration**
  - Turning `op_runtime_summary.json` into a validation job output (e.g., `runtime:op-signatures`) with simple “mismatch budget” thresholds would make regressions and new mismatches show up automatically when promotion decisions are made.

## Summary

An agent reading this file and `Notes.md` should understand that:
- This suite piggybacks on `runtime-adversarial` to provide a per-operation runtime scorecard.
- For `file-read*` and `mach-lookup`, runtime behavior largely matches static expectations; the main systematic discrepancy is `/tmp`→`/private/tmp` canonicalization, which we treat as out-of-model for PolicyGraph (see `book/experiments/vfs-canonicalization/Report.md`, mapped).
- The same mechanism can be extended to more operations and richer signals (signatures, profile layers) when we are ready to deepen runtime coverage.***
