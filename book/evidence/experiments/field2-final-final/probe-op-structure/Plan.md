# Probe Op Structure – Plan

## Purpose
Add a minimal runtime slice to test whether anchors surfaced in the structural
analysis produce the expected allow/deny outcomes under SBPL on this host.

## Baseline & scope
- World: `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
- Scope: file-read* (`/tmp/foo`, `/etc/hosts`), mach-lookup
  (`com.apple.cfprefsd.agent`), and iokit-open* anchors
  (`IOUSBHostInterface`, `IOSurfaceRootUserClient`).
- Runtime results are provisional unless clean, decision-stage outcomes are observed.

## Inputs
- SBPL profiles under `book/evidence/experiments/field2-final-final/probe-op-structure/sb/`:
  - `v1_file_require_any.sb`
  - `v3_mach_global_local.sb`
  - `v5_iokit_class_property.sb`
  - `v9_iokit_user_client_only.sb`
  - `v10_iokit_user_client_pair.sb`
  - `v11_iokit_user_client_connection.sb`
- Runtime harness: `python -m book.api.runtime run`.

## Outputs
- `book/evidence/experiments/runtime-final-final/suites/field2-probe-op-structure/plan.json`
- `book/evidence/experiments/field2-final-final/probe-op-structure/registry/{profiles,probes}.json`
- Runtime artifacts under `book/evidence/experiments/field2-final-final/probe-op-structure/out/`
  (expected matrix, runtime results, normalized events, run manifest).

## Steps
1) Add plan + registry descriptors and register the runtime registry.
2) Preflight scan the SBPL inputs to flag known apply-gate signatures.
3) Run the plan via `--channel launchd_clean` and capture outputs.
4) Update `Notes.md` and `Report.md` with results and scope notes.

## Plan B (pre-planned)
- If `sandbox_mach_probe` or `sandbox_iokit_probe` fails at apply/boot, skip
  those probes and record them as `blocked`, leaving anchors structural-only.
- If IOKit property constraints are ambiguous, add a class-only SBPL variant
  and rerun the IOKit lane; if still ambiguous, record as `blocked`.
