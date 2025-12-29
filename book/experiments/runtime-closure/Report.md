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
- File canonicalization lane: partial (runtime run recorded; mismatches remain).
- Mach service discrimination lane: ok (baseline confirms missing control).
- IOKit lane: partial (baseline open succeeds; sandboxed probe denied).

## Lanes

### File canonicalization
Profiles test `/etc/hosts` vs `/private/etc/hosts` with a `/tmp/foo` control. The goal is to separate canonicalization effects from policy outcomes and feed the `/etc/hosts` anchor ambiguity in `probe-op-structure`.

Observed (run: `out/5a8908d8-d626-4cac-8bdd-0f53c02af8fe/`):
- `/etc/hosts` denied under all three profiles, including the both-paths profile.
- `/private/etc/hosts` allowed under the private-only and both profiles; denied under alias-only.
- `/tmp/foo` denied under all three profiles (baseline resolves `/tmp/foo` -> `/private/tmp/foo`).
- `path_witnesses.json` baseline confirms `/etc/hosts` -> `/private/etc/hosts`. Scenario successes record `F_GETPATH_NOFIRMLINK:/System/Volumes/Data/private/etc/hosts` for the `/private/etc/hosts` allow path.

This strengthens the canonicalization mismatch hypothesis and suggests that firmlink spelling may be relevant when `/etc/hosts` is requested under deny-default rules.

### Mach service discrimination
One profile allows `mach-lookup` for a known service and a missing control name. Baseline vs scenario outcomes distinguish “missing service” from “sandbox denial.”

Observed (run: `out/66315539-a0ce-44bf-bff0-07a79f205fea/`):
- `com.apple.cfprefsd.agent` allowed in baseline and scenario (`kr=0`).
- `com.apple.sandbox-lore.missing` returns `kr=1102` in baseline and scenario (missing service), so the “deny” result is not a sandbox decision on this host.

### IOKit
Profiles probe a class verified as present in baseline to avoid false “not found” results. The goal is a discriminating runtime signal for IOKit anchors.

Observed (run: `out/48086066-bfa2-44bb-877c-62dd1dceca09/`):
- Baseline `iokit_probe` for `IOSurfaceRoot` returns `found=true` and `open_kr=0`.
- Scenario `sandbox_iokit_probe` returns `found=true` with `open_kr=-536870174` and `EPERM` (deny at probe stage), so the lane is discriminating but not yet aligned with the allow expectation.

## Evidence & artifacts
- Runtime plan/registry: `book/experiments/runtime-closure/plan.json` and `registry/{probes.json,profiles.json}`.
- SBPL profiles: `book/experiments/runtime-closure/sb/*.sb`.
- Run bundles: `book/experiments/runtime-closure/out/<run_id>/`.
  - File lane: `book/experiments/runtime-closure/out/5a8908d8-d626-4cac-8bdd-0f53c02af8fe/` (includes `path_witnesses.json`).
  - Mach lane: `book/experiments/runtime-closure/out/66315539-a0ce-44bf-bff0-07a79f205fea/`.
  - IOKit lane: `book/experiments/runtime-closure/out/48086066-bfa2-44bb-877c-62dd1dceca09/`.

## Limitations
- Apply-stage gating is blocked evidence; failures at apply/exec are not policy outcomes.
- Missing services/classes are not denials and must be resolved via baseline lane.
- `/etc/hosts` remains unresolved when spelled as `/etc/...` even in both-paths profiles; firmlink spellings may be required for a clean allow control.
- The IOKit lane shows a baseline-open vs sandbox-deny split for `IOSurfaceRoot`, but the allow expectation is not yet satisfied; treat as hypothesis until reconciled.
