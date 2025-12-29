- world_id: sonoma-14.4.1-23E224-arm64-dyld-2c0602c5
- tier: hypothesis (runtime); mapped only when paired with structural anchor bindings
- primary outputs: out/<run_id>/{runtime_results.json,runtime_events.normalized.json,run_manifest.json,artifact_index.json,path_witnesses.json}
- upstream structure: book/experiments/probe-op-structure/Report.md
- runtime harness: book/api/runtime (plan/registry execution, launchd_clean channel)

# Runtime Closure – Research Report (Sonoma baseline)

## Purpose
Provide narrow, stage-labeled runtime evidence that helps close gaps in `probe-op-structure`. The focus is on canonicalization ambiguity (`/etc` vs `/private/etc`), mach service presence vs denial, and IOKit class presence vs denial. This experiment does not claim semantics beyond operation-stage outcomes paired with structural anchor bindings.

## Baseline & scope
- World: `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
- Runtime channel: `launchd_clean` only for decision-stage evidence.
- Preflight: `book/tools/preflight/preflight.py scan` on all SBPL inputs.
- Profiles: minimal deny-default SBPL with explicit allow rules for the targeted anchors.

## Status
- File canonicalization lane: partial (v2 spelling matrix run; `/etc` still unresolved).
- Mach service discrimination lane: ok (baseline confirms missing control).
- IOKit lane: partial (service-only and user-client-only deny open; both allow open but post-open call fails even in baseline).

## Lanes

### File canonicalization
Profiles test alias (`/etc` + `/tmp`), private, and Data spellings as literal-only rules for `/etc/hosts` and `/tmp/foo`. The goal is to separate spelling and firmlink effects from policy outcomes.

Observed (run: `out/ea704c9c-5102-473a-b942-e24af4136cc8/`):
- Alias profile (`v2_alias_literals`) denies all six probes at operation stage.
- Private profile (`v2_private_literals`) allows `/private/etc/hosts`, `/System/Volumes/Data/private/etc/hosts`, `/private/tmp/foo`, `/System/Volumes/Data/private/tmp/foo`, and `/tmp/foo`; `/etc/hosts` remains denied.
- Data profile (`v2_data_literals`) denies all six probes, including the Data spellings, at operation stage.
- `path_witnesses.json` baseline shows `/etc/hosts` -> `/private/etc/hosts` and `/tmp/foo` -> `/private/tmp/foo`. Scenario successes report `F_GETPATH_NOFIRMLINK:/System/Volumes/Data/private/...` for the private profile.
All three profiles compile and apply successfully (`sandbox_init` rc=0); failures are operation-stage (`failure_stage: probe`).

Interpretation (bounded):
- `/tmp/foo` fits the “alias fails, private succeeds” bucket: the private literal rule allows alias and Data spellings, suggesting canonicalization to `/private/tmp` at operation time.
- `/etc/hosts` remains unresolved: private spelling allows `/private/etc/hosts` and Data spellings, but the alias spelling (`/etc/hosts`) still denies.

### Mach service discrimination
One profile allows `mach-lookup` for a known service and a missing control name. Baseline vs scenario outcomes distinguish “missing service” from “sandbox denial.”

Observed (run: `out/66315539-a0ce-44bf-bff0-07a79f205fea/`):
- `com.apple.cfprefsd.agent` allowed in baseline and scenario (`kr=0`).
- `com.apple.sandbox-lore.missing` returns `kr=1102` in baseline and scenario (missing service), so the “deny” result is not a sandbox decision on this host.

### IOKit
Profiles target IOSurfaceRoot via user-client-class filters to align with anchor-level structure.

Observed (runs: `out/6ecc929d-fec5-4206-a85c-e3e265c349a7/`, `out/08887f36-f87b-45ff-8e9e-6ee7eb9cb635/`, `out/33ff5a68-262a-4a8c-b427-c7cb923a3adc/`, `out/fae371c2-f2f5-470f-b672-cf0c3e24d6c0/`):
- `v2_user_client_only` (`iokit-open-user-client`) allows `IOSurfaceRoot` (`open_kr=0`) at operation stage.
- `v4_iokit_open_user_client` (`iokit-open`) allows `IOSurfaceRoot` (`open_kr=0`) at operation stage.
- `v3_connection_user_client` denies with `open_kr=-536870174` and `EPERM` at operation stage.
- `v5_service_only` (`iokit-open-service` allow + user-client deny) returns `open_kr=-536870174` (EPERM); post-open call not attempted.
- `v6_user_client_only` (`iokit-open-user-client` allow + service deny) returns `open_kr=-536870174` (EPERM); post-open call not attempted.
- `v7_service_user_client_both` (allow both ops) returns `open_kr=0` with `call_kr=-536870206` from `IOConnectCallMethod`.
All profiles apply successfully (`sandbox_init` rc=0). The post-open call returns `call_kr=-536870206` even when unsandboxed (`book/api/runtime/native/probes/iokit_probe IOSurfaceRoot`), so Action B is not discriminating on this host.

This indicates the user-client-class filter is sufficient for the IOSurfaceRoot probe, while the IOAccelerator connection constraint is too narrow on this host.

## Evidence & artifacts
- Runtime plan/registry: `book/experiments/runtime-closure/plan.json` and `registry/{probes.json,profiles.json}`.
- SBPL profiles: `book/experiments/runtime-closure/sb/*.sb`.
- Run bundles: `book/experiments/runtime-closure/out/<run_id>/`.
  - File lane (v2 matrix): `book/experiments/runtime-closure/out/ea704c9c-5102-473a-b942-e24af4136cc8/` (includes `path_witnesses.json` and `promotion_packet.json`).
  - Mach lane: `book/experiments/runtime-closure/out/66315539-a0ce-44bf-bff0-07a79f205fea/`.
  - IOKit op-identity lane: `book/experiments/runtime-closure/out/6ecc929d-fec5-4206-a85c-e3e265c349a7/`, `book/experiments/runtime-closure/out/08887f36-f87b-45ff-8e9e-6ee7eb9cb635/`, `book/experiments/runtime-closure/out/33ff5a68-262a-4a8c-b427-c7cb923a3adc/`, `book/experiments/runtime-closure/out/fae371c2-f2f5-470f-b672-cf0c3e24d6c0/`.
  - Prior runs: `book/experiments/runtime-closure/out/5a8908d8-d626-4cac-8bdd-0f53c02af8fe/` (file v1) and `book/experiments/runtime-closure/out/48086066-bfa2-44bb-877c-62dd1dceca09/` (IOKit v1).
- Mapped VFS update: `book/graph/mappings/vfs_canonicalization/path_canonicalization_map.json` (now includes the runtime-closure file matrix packet).

## Limitations
- Apply-stage gating is blocked evidence; failures at apply/exec are not policy outcomes.
- Missing services/classes are not denials and must be resolved via baseline lane.
- `/etc/hosts` remains unresolved when spelled as `/etc/...` even when private and Data spellings are allowed.
- Data-only literal rules do not allow Data spellings on this host, suggesting enforcement compares a different spelling; this remains hypothesis-level without a direct kernel witness at operation time.
- `with report` is not accepted on deny rules in this harness, so the initial tri-matrix attempt (`out/1034a7bd-81e1-41a1-9897-35f5556800c7/`) failed at apply stage and is treated as blocked evidence.
