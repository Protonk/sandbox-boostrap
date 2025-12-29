- world_id: sonoma-14.4.1-23E224-arm64-dyld-2c0602c5
- tier: mapped (structural); runtime slice: partial (hypothesis)
- primary outputs: out/analysis.json; out/anchor_hits.json; out/tag_inventory.json; out/tag_layout_hypotheses.json; out/literal_scan.json; out/tag_bytes.json
- runtime outputs: out/39f84aa5-86b4-466d-b5d9-f510299bbd0a/{runtime_results.json,runtime_events.normalized.json,run_manifest.json}
- upstream IR: book/api/profile_tools/decoder.py; book/graph/mappings/tag_layouts/tag_layouts.json; book/graph/mappings/vocab/filters.json
- downstream mappings: book/graph/mappings/anchors/anchor_filter_map.json; book/experiments/field2-filters/out/*
- guardrails: book/tests/test_anchor_filter_alignment.py; book/tests/test_mappings_guardrail.py

# Probe Op Structure – Research Report (Sonoma baseline)

## Purpose
Build an anchor-aware structural view of `field2` usage across operations and filters on this host. The core question is: which filters show up in `field2` on which nodes/tags for concrete anchors like `/etc/hosts`, `/tmp/foo`, `flow-divert`, `com.apple.cfprefsd.agent`, and `IOUSBHostInterface`? The structural evidence is mapped and feeds `anchor_filter_map.json`. A minimal runtime slice exists to falsify or corroborate a few anchor-level expectations, but it is intentionally narrow.

## Baseline & scope
- World: `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
- Vocab: `book/graph/mappings/vocab/ops.json` and `book/graph/mappings/vocab/filters.json` (both `status: ok`).
- Profiles:
  - Probe SBPL variants under `book/experiments/probe-op-structure/sb/` with compiled blobs in `sb/build/`.
  - Canonical system blobs: `book/graph/concepts/validation/fixtures/blobs/{airlock,bsd,sample}.sb.bin`.
- Decoder backbone: `book/api/profile_tools/decoder.py` with canonical layouts from `book/graph/mappings/tag_layouts/tag_layouts.json` (`status: ok`).
- Runtime slice: `book/experiments/probe-op-structure/plan.json` and registry data under `registry/`.

## Status
- Structural evidence: **mapped** (anchor_hits + tag layouts + guardrails).
- Runtime slice: **partial/hypothesis** (one small plan run; mismatches and non-discriminating probes recorded).

## Method summary (structural)
1) **Probe matrix**: SBPL profiles `v0`–`v8` exercise file, mach, network, and iokit filters with distinct anchors.
2) **Decode + slice**: decoder consumes canonical tag layouts and segment-aware slicing to extract nodes, tags, and `field2` payloads.
3) **Anchor scan**: `anchor_scan.py` resolves anchors to literal offsets and node indices using decoder `literal_refs` plus byte scans when needed.
4) **Integration**: `anchor_hits.json` feeds `book/graph/mappings/anchors/anchor_filter_map.json` with guardrails enforcing alignment.

## Structural findings

### Generic filter dominance in probes
- File probes are dominated by `path`, `ipc-posix-name`, `global-name`, and `local-name`.
- Mach/iokit probes mostly surface `global-name` and `local-name` payloads, with occasional `path`.
- Network probes are dominated by `remote` and `local`, with occasional `xattr` and a triple-only token (`2560`).

### System profile tag context (structural)
- `sys:bsd` now decodes tags 26/27 under the canonical layouts; `field2` payloads align with the host filter vocabulary in the current framing.
- `sys:airlock` still carries high/out-of-vocab payloads in some tags; those remain opaque and are tracked in `field2-filters`.
- `sys:sample` mixes low IDs with a small set of high payloads (e.g. 3584) and keeps `/etc/hosts` as a multi-filter anchor.

### Anchor → node → `field2` summary (structural)

| anchor                    | status (mapping)            | filter_id | filter_name    | field2_values (structural) |
|---------------------------|-----------------------------|-----------|----------------|----------------------------|
| `/tmp/foo`                | solid (partial)             | 0         | path           | 0, 4, 5, 6                 |
| `/etc/hosts`              | solid (partial)             | 0         | path           | 0, 1, 5, 6, 7, 3584        |
| `/var/log`                | solid (partial)             | 4         | ipc-posix-name | 4                          |
| `idVendor`                | solid (partial)             | 6         | local-name     | 6                          |
| `preferences/logging`     | solid (partial)             | 5         | global-name    | 5                          |
| `com.apple.cfprefsd.agent`| blocked (candidates only)   | —         | —              | 0, 4, 5, 6                 |
| `flow-divert`             | blocked (candidates only)   | —         | —              | 2, 7, 2560                 |
| `IOUSBHostInterface`      | blocked (candidates only)   | —         | —              | 0, 5, 6                    |

Use the “solid” rows for structural anchor→Filter references on this host. Blocked rows are explicitly unresolved and should not be promoted.

## Runtime slice (launchd clean)
A minimal runtime plan exists to test a few anchors under the shared runtime harness.

- Plan: `book/experiments/probe-op-structure/plan.json` (registry `probe-op-structure`).
- Latest run: `book/experiments/probe-op-structure/out/39f84aa5-86b4-466d-b5d9-f510299bbd0a/` (see `book/experiments/probe-op-structure/out/LATEST`).
- Outcomes:
  - `file-read* /tmp/foo` allowed.
  - `file-read* /etc/hosts` denied (`open target: Operation not permitted`); unsandboxed path observation reports `/private/etc/hosts`, suggesting a canonicalization mismatch.
  - `mach-lookup com.apple.cfprefsd.agent` allowed under `sandbox_mach_probe`.
  - `iokit-open-service IOUSBHostInterface` not found (`{"found":false}`), so this probe is non-discriminating for policy semantics.

This runtime slice is intentionally narrow and should be treated as hypothesis-level evidence unless additional controls are added.

Additional runtime closure (file-only) lives in `book/experiments/runtime-closure/Report.md`. The file lane run `book/experiments/runtime-closure/out/5a8908d8-d626-4cac-8bdd-0f53c02af8fe/` denies `/etc/hosts` under alias-only, private-only, and both profiles while allowing `/private/etc/hosts` only when explicitly permitted; `/tmp/foo` is denied across all three profiles. `path_witnesses.json` in that run shows baseline `/etc/hosts` -> `/private/etc/hosts` and scenario `F_GETPATH_NOFIRMLINK:/System/Volumes/Data/private/etc/hosts` when `/private/etc/hosts` opens successfully, reinforcing the canonicalization mismatch hypothesis.

The runtime-closure mach lane run `book/experiments/runtime-closure/out/66315539-a0ce-44bf-bff0-07a79f205fea/` confirms `com.apple.cfprefsd.agent` succeeds in baseline and scenario (`kr=0`), while the missing-service control returns `kr=1102` in both lanes, helping separate “missing service” from sandbox denial.

The runtime-closure IOKit lane run `book/experiments/runtime-closure/out/48086066-bfa2-44bb-877c-62dd1dceca09/` uses the `IOSurfaceRoot` class: baseline `iokit_probe` opens successfully (`open_kr=0`), while the sandboxed probe reports `open_kr=-536870174` with `EPERM`, providing a discriminating IOKit signal that is not yet aligned with the allow expectation.

The runtime-closure file spelling matrix run `book/experiments/runtime-closure/out/ea704c9c-5102-473a-b942-e24af4136cc8/` shows alias-only rules failing for both `/etc/hosts` and `/tmp/foo`, while private spelling rules allow `/private/...` and `/System/Volumes/Data/private/...` spellings (and `/tmp/foo`) at operation stage. `/etc/hosts` remains denied under the alias spelling even when private and Data spellings are allowed, so the `/etc` anchor is still unresolved. The same run shows `IOSurfaceRootUserClient` rules flipping `IOSurfaceRoot` to allow under the user-client-class profile (`v2_user_client_only`), while adding the `IOAccelerator` connection constraint returns `EPERM` (`v3_connection_user_client`).

## Evidence & artifacts
- Structural outputs: `book/experiments/probe-op-structure/out/{analysis.json,anchor_hits.json,tag_inventory.json,tag_layout_hypotheses.json,tag_bytes.json,literal_scan.json}`.
- Runtime outputs: `book/experiments/probe-op-structure/out/39f84aa5-86b4-466d-b5d9-f510299bbd0a/{runtime_results.json,runtime_events.normalized.json,run_manifest.json}`.
- Shared mappings: `book/graph/mappings/tag_layouts/tag_layouts.json`, `book/graph/mappings/anchors/anchor_filter_map.json`.

## Guardrails
- `book/tests/test_mappings_guardrail.py` ensures tag layouts and core mappings stay pinned to this world.
- `book/tests/test_anchor_filter_alignment.py` enforces that `anchor_filter_map.json` stays aligned with `out/anchor_hits.json`.

## Running and refreshing
- Structural refresh:
  - `python3 book/experiments/probe-op-structure/analyze_profiles.py`
  - `python3 book/experiments/probe-op-structure/anchor_scan.py`
- Runtime slice:
  - `python -m book.api.runtime run --plan book/experiments/probe-op-structure/plan.json --channel launchd_clean --out book/experiments/probe-op-structure/out`

## Limitations and non-claims
- Literal/regex operands are still partial; some anchor bindings rely on heuristic scans.
- Generic scaffolding filters dominate many probe graphs; this experiment does not isolate all fine-grained filters.
- High `field2` values (e.g., 16660 in `sys:bsd`, 165/166/10752 in `sys:airlock`, 2560 in `flow-divert`, 3584 in `sys:sample`) are structurally bounded but semantically unmapped.
- Blocked anchors in `anchor_filter_map.json` (e.g., `flow-divert`, `com.apple.cfprefsd.agent`, `IOUSBHostInterface`) remain unresolved.
- Runtime results here are narrow and should not be treated as canonical policy semantics without broader runtime evidence.

## Next steps
1) Add discriminating SBPL variants for blocked anchors (e.g., separate `global-name` vs `local-name` for `com.apple.cfprefsd.agent`).
2) Add an IOKit class-only profile if the property filter remains non-discriminating.
3) Re-run the runtime slice after adding controls and note any changes in `runtime_results.json`.
