# Report – mach-name-equivalence

## Purpose

Determine whether `mach-lookup` and `mach-register` induce the same name-equivalence relationship for global names when a profile allows AA and deny-defaults everything else.

## Baseline & scope

- World: `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
- Evidence source: committed runtime bundle (`launchd_clean`) from `book.api.runtime`.
- Scope: AA = `com.apple.cfprefsd.agent`, BB = `com.apple.cfprefsd.agent.sandboxlore`.

## How to run
Run via the runtime CLI and treat the committed bundle as the authority (`out/LATEST` points to the most recent committed run):

```sh
python -m book.api.runtime run \
  --plan book/evidence/experiments/runtime-final-final/suites/mach-name-equivalence/plan.json \
  --channel launchd_clean \
  --out book/evidence/experiments/runtime-final-final/suites/mach-name-equivalence/out
```

## Results

- `mach-lookup` (resolve) shows AA allowed and BB denied at operation stage under the profile.
- `mach-register` (publish) has no operation-stage witness; the probe path uses `sandbox_runner -- true` plus oracle callouts, so publish semantics are not established.

## Evidence & artifacts

- Bundle: `book/evidence/experiments/runtime-final-final/suites/mach-name-equivalence/out/e3ff212f-9e01-4eb9-bb59-ce6385bdc848/`.
- Operation-stage records: `book/evidence/experiments/runtime-final-final/suites/mach-name-equivalence/out/e3ff212f-9e01-4eb9-bb59-ce6385bdc848/runtime_events.normalized.json`.
- Commit barrier: `book/evidence/experiments/runtime-final-final/suites/mach-name-equivalence/out/e3ff212f-9e01-4eb9-bb59-ce6385bdc848/artifact_index.json`.

## Status

- `mach-lookup`: ok (mapped, scenario lane, operation stage).
- `mach-register`: blocked (no operation-stage probe in current toolchain).
