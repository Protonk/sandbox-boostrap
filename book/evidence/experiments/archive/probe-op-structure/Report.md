- world_id: sonoma-14.4.1-23E224-arm64-dyld-2c0602c5
- tier: mapped (structural); runtime slice: partial (hypothesis)
- primary outputs: out/analysis.json; out/anchor_hits.json; out/anchor_hits_delta.json; out/tag_inventory.json; out/tag_layout_hypotheses.json; out/literal_scan.json; out/tag_bytes.json
- runtime outputs: out/39f84aa5-86b4-466d-b5d9-f510299bbd0a/{runtime_results.json,runtime_events.normalized.json,run_manifest.json}
- upstream IR: book/api/profile/decoder/; book/evidence/graph/mappings/tag_layouts/tag_layouts.json; book/evidence/graph/mappings/vocab/filters.json
- downstream mappings: book/evidence/graph/mappings/anchors/anchor_filter_map.json; book/evidence/experiments/field2-final-final/field2-filters/out/*
- guardrails: book/tests/planes/graph/test_anchor_filter_alignment.py; book/tests/planes/graph/test_mappings_guardrail.py

# Probe Op Structure – Research Report (Sonoma baseline)

## Purpose
Build an anchor-aware structural view of `field2` usage across operations and filters on this host. The core question is: which filters show up in `field2` on which nodes/tags for concrete anchors like `/etc/hosts`, `/tmp/foo`, `flow-divert`, `com.apple.cfprefsd.agent`, and `IOUSBHostInterface`? The structural evidence is mapped and feeds `anchor_filter_map.json`. A minimal runtime slice exists to falsify or corroborate a few anchor-level expectations, but it is intentionally narrow.

## Baseline & scope
- World: `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
- Vocab: `book/evidence/graph/mappings/vocab/ops.json` and `book/evidence/graph/mappings/vocab/filters.json` (both `status: ok`).
- Profiles:
  - Probe SBPL variants under `book/evidence/experiments/field2-final-final/probe-op-structure/sb/` with compiled blobs in `sb/build/`.
  - Canonical system blobs: `book/evidence/graph/concepts/validation/fixtures/blobs/{airlock,bsd,sample}.sb.bin`.
- Decoder backbone: `book/api/profile/decoder/` with canonical layouts from `book/evidence/graph/mappings/tag_layouts/tag_layouts.json` (`status: ok`).
- Runtime slice: `book/evidence/experiments/field2-final-final/probe-op-structure/plan.json` and registry data under `registry/`.

## Status
- Structural evidence: **mapped** (anchor_hits + tag layouts + guardrails).
- Runtime slice: **partial/hypothesis** (one small plan run; mismatches and non-discriminating probes recorded).

## Method summary (structural)
1) **Probe matrix**: SBPL profiles `v0`–`v8` exercise file, mach, network, and iokit filters with distinct anchors.
2) **Decode + slice**: decoder consumes canonical tag layouts and segment-aware slicing to extract nodes, tags, and `field2` payloads.
3) **Anchor scan**: `anchor_scan.py` resolves anchors to literal offsets and node indices using decoder `literal_refs` plus byte scans when needed.
4) **Integration**: `anchor_hits.json` feeds `book/evidence/graph/mappings/anchors/anchor_filter_map.json` with guardrails enforcing alignment.

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
| `IOSurfaceRootUserClient` | solid (partial)             | 1         | mount-relative-path | 1                      |
| `IOHIDParamUserClient`    | blocked (candidates: path / mount-relative-path) | — | — | 0, 1, 4, 18753            |
| `IOAccelerator`           | blocked (candidates: mount-relative-path / global-name / path) | — | — | 0, 1, 5                  |

Use the “solid” rows for structural anchor→Filter references on this host. Blocked rows are explicitly unresolved and should not be promoted.

## Runtime slice (launchd clean)
A minimal runtime plan exists to test a few anchors under the shared runtime harness.

- Plan: `book/evidence/experiments/field2-final-final/probe-op-structure/plan.json` (registry `probe-op-structure`).
- Latest run: `book/evidence/experiments/field2-final-final/probe-op-structure/out/39f84aa5-86b4-466d-b5d9-f510299bbd0a/` (see `book/evidence/experiments/field2-final-final/probe-op-structure/out/LATEST`).
- Outcomes:
  - `file-read* /tmp/foo` allowed.
  - `file-read* /etc/hosts` denied (`open target: Operation not permitted`); unsandboxed path observation reports `/private/etc/hosts`, suggesting a canonicalization mismatch.
  - `mach-lookup com.apple.cfprefsd.agent` allowed under `sandbox_mach_probe`.
  - `iokit-open-service IOUSBHostInterface` not found (`{"found":false}`), so this probe is non-discriminating for policy semantics.

This runtime slice is intentionally narrow and should be treated as hypothesis-level evidence unless additional controls are added.

Additional runtime closure (file-only) lives in `book/evidence/experiments/runtime-closure/Report.md`. The file lane run `book/evidence/experiments/runtime-closure/out/5a8908d8-d626-4cac-8bdd-0f53c02af8fe/` denies `/etc/hosts` under alias-only, private-only, and both profiles while allowing `/private/etc/hosts` only when explicitly permitted; `/tmp/foo` is denied across all three profiles. `path_witnesses.json` in that run shows baseline `/etc/hosts` -> `/private/etc/hosts` and scenario `F_GETPATH_NOFIRMLINK:/System/Volumes/Data/private/etc/hosts` when `/private/etc/hosts` opens successfully, reinforcing the canonicalization mismatch hypothesis.

The runtime-closure mach lane run `book/evidence/experiments/runtime-closure/out/66315539-a0ce-44bf-bff0-07a79f205fea/` confirms `com.apple.cfprefsd.agent` succeeds in baseline and scenario (`kr=0`), while the missing-service control returns `kr=1102` in both lanes, helping separate “missing service” from sandbox denial.

The runtime-closure IOKit lane run `book/evidence/experiments/runtime-closure/out/48086066-bfa2-44bb-877c-62dd1dceca09/` uses the `IOSurfaceRoot` class: baseline `iokit_probe` opens successfully (`open_kr=0`), while the sandboxed probe reports `open_kr=-536870174` with `EPERM`, providing a discriminating IOKit signal that is not yet aligned with the allow expectation.
Structural anchor scans now include `IOSurfaceRootUserClient` from `v9_iokit_user_client_only`, `v10_iokit_user_client_pair`, and `v11_iokit_user_client_connection`. A literal-pool compression on this host drops leading `IO` prefixes for some IOKit strings, so `anchor_scan.py` treats `IO*` anchors as matches when the stripped literal matches the anchor minus the `IO` prefix. To avoid widening contexts, delta attribution now compares a deny-default control (`v12_iokit_control`) against the v9 IOSurface variant and emits `out/anchor_hits_delta.json`. The anchor generator uses this delta for IOSurfaceRootUserClient, restricting to filter-vocab nodes and excluding the generic `path` filter. As a result, `anchor_filter_map.json` now exposes a single `mount-relative-path` binding for IOSurfaceRootUserClient. The paired `IOHIDParamUserClient` anchor and the `IOAccelerator` co-anchor remain blocked due to mixed contexts and are kept as structural hints only.
An op-identity tri-matrix under `book/evidence/experiments/runtime-closure/out/fae371c2-f2f5-470f-b672-cf0c3e24d6c0/` shows `iokit-open-service`-only and `iokit-open-user-client`-only profiles both deny `IOSurfaceRoot` (`open_kr=-536870174`), while the profile that allows both ops opens successfully but the post-open `IOConnectCallMethod` still fails (`call_kr=-536870206`). The same post-open call fails unsandboxed (`book/api/runtime/native/probes/iokit_probe IOSurfaceRoot`), so the op identity remains ambiguous and the post-open action is not discriminating on this host without a different user-client call or an observer-lane witness.

The runtime-closure file spelling matrix run `book/evidence/experiments/runtime-closure/out/ea704c9c-5102-473a-b942-e24af4136cc8/` shows alias-only rules failing for both `/etc/hosts` and `/tmp/foo`, while private spelling rules allow `/private/...` and `/System/Volumes/Data/private/...` spellings (and `/tmp/foo`) at operation stage. `/etc/hosts` remains denied under the alias spelling even when private and Data spellings are allowed, so the `/etc` anchor is still unresolved. The same run shows `IOSurfaceRootUserClient` rules flipping `IOSurfaceRoot` to allow under the user-client-class profile (`v2_user_client_only`), while adding the `IOAccelerator` connection constraint returns `EPERM` (`v3_connection_user_client`).

## Evidence & artifacts
- Structural outputs: `book/evidence/experiments/field2-final-final/probe-op-structure/out/{analysis.json,anchor_hits.json,anchor_hits_delta.json,tag_inventory.json,tag_layout_hypotheses.json,tag_bytes.json,literal_scan.json}`.
- Runtime outputs: `book/evidence/experiments/field2-final-final/probe-op-structure/out/39f84aa5-86b4-466d-b5d9-f510299bbd0a/{runtime_results.json,runtime_events.normalized.json,run_manifest.json}`.
- Shared mappings: `book/evidence/graph/mappings/tag_layouts/tag_layouts.json`, `book/evidence/graph/mappings/anchors/anchor_filter_map.json`.

## Guardrails
- `book/tests/planes/graph/test_mappings_guardrail.py` ensures tag layouts and core mappings stay pinned to this world.
- `book/tests/planes/graph/test_anchor_filter_alignment.py` enforces that `anchor_filter_map.json` stays aligned with `out/anchor_hits.json` (or `out/anchor_hits_delta.json` for delta-attributed anchors).

## How to run
Run via the runtime CLI and treat the run-scoped bundle as the authority (`out/LATEST` points to the most recent committed run):

```sh
python -m book.api.runtime run \
  --plan book/evidence/experiments/field2-final-final/probe-op-structure/plan.json \
  --channel launchd_clean \
  --out book/evidence/experiments/field2-final-final/probe-op-structure/out
```

## Structural refresh
- `python3 book/evidence/experiments/field2-final-final/probe-op-structure/analyze_profiles.py`
- `python3 book/evidence/experiments/field2-final-final/probe-op-structure/anchor_scan.py`

## Limitations and non-claims
- Literal/regex operands are still partial; some anchor bindings rely on heuristic scans.
- Generic scaffolding filters dominate many probe graphs; this experiment does not isolate all fine-grained filters.
- High `field2` values (e.g., 16660 in `sys:bsd`, 165/166/10752 in `sys:airlock`, 2560 in `flow-divert`, 3584 in `sys:sample`) are structurally bounded but semantically unmapped.
- Blocked anchors in `anchor_filter_map.json` (e.g., `flow-divert`, `com.apple.cfprefsd.agent`, `IOUSBHostInterface`) remain unresolved.
- Runtime results here are narrow and should not be treated as canonical policy semantics without broader runtime evidence.

## Next steps
1) If IOSurface op identity remains ambiguous, add an observer-lane run (sandbox log capture) to disambiguate `iokit-open` vs `iokit-open-user-client` without adding more SBPL variants.
2) Add discriminating SBPL variants for blocked anchors outside IOKit (e.g., separate `global-name` vs `local-name` for `com.apple.cfprefsd.agent`).
3) Re-run the runtime slice after adding controls and note any changes in `runtime_results.json`.
