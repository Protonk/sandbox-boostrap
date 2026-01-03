- world_id: sonoma-14.4.1-23E224-arm64-dyld-2c0602c5
- tier: hypothesis (runtime); mapped only when paired with structural anchor bindings
- primary outputs: out/<run_id>/{runtime_results.json,runtime_events.normalized.json,run_manifest.json,artifact_index.json,path_witnesses.json}
- upstream structure: book/evidence/experiments/field2-final-final/probe-op-structure/Report.md
- runtime harness: book/api/runtime (plan/registry execution, launchd_clean channel)

# Runtime Closure – Research Report (Sonoma baseline)

## Purpose
Provide narrow, stage-labeled runtime evidence that helps close gaps in `probe-op-structure`. The focus is on canonicalization ambiguity (`/etc` vs `/private/etc`), mach service presence vs denial, and IOKit class presence vs denial. This experiment does not claim semantics beyond operation-stage outcomes paired with structural anchor bindings.

## Baseline & scope
- World: `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
- Runtime channel: `launchd_clean` only for decision-stage evidence.
- Preflight: `book/tools/preflight/preflight.py scan` on all SBPL inputs.
- Profiles: minimal deny-default SBPL with explicit allow rules for the targeted anchors.

## How to run
Run via the runtime CLI so the committed bundle is the authority (`out/LATEST` points to the most recent committed run):

```sh
python -m book.api.runtime run \
  --plan book/evidence/experiments/runtime-closure/plan.json \
  --channel launchd_clean \
  --out book/evidence/experiments/runtime-closure/out
```

## Status
- File canonicalization lane: partial (v2 spelling matrix run; `/etc` still unresolved).
- Mach service discrimination lane: ok (baseline confirms missing control).
- Oracle calibration lane: blocked (sandbox_check denies even when the operation allows on this host).
- IOKit lane: partial (service-only and user-client-only deny open; both allow open but post-open call still fails; replay shows the captured call shape is invalid in baseline and sandbox, so the post-open failure is a call-shape issue rather than a sandbox gate on this host; message-filter variants are blocked by preflight apply-gate signatures).

## IOKit lane reference summary (IOKIT.md)
The consolidated IOKit lane reference lives in `book/evidence/experiments/runtime-closure/IOKIT.md` and records the current closure point: post-open IOSurface work still returns `kIOReturnBadArgument` in both baseline and sandbox, so it is not a sandbox gate claim at this stage. The summary table in that document points to the method-0 sweep (`book/evidence/experiments/runtime-closure/out/iosurface_method0_sweep.json`), binary payload attempt (`book/evidence/experiments/runtime-closure/out/iosurface_method0_binary.json`), v7 method-0 run (`book/evidence/experiments/runtime-closure/out/289b183e-d86e-47db-ae57-0b9bd3541c6a/runtime_events.normalized.json`), and replay run (`book/evidence/experiments/runtime-closure/out/e720b256-2f6e-4888-9288-2e19b5007fa9/runtime_events.normalized.json`).

## Failures ledger summary (Failures.md)
The negative knowledge from this experiment is captured in `book/evidence/experiments/runtime-closure/Failures.md` and is meant to prevent re-running known dead ends. It highlights the method-0 selector sweep failure (`book/evidence/experiments/runtime-closure/out/iosurface_method0_sweep.json`), the mach capture blind spot (`book/evidence/experiments/runtime-closure/out/iosurface_mach_capture.json`), the apply-gated external-method profile (`book/evidence/experiments/runtime-closure/out/03aaad16-f06b-4ec7-a468-c6379abbeb4d/mismatch_summary.json`), and the uncalibrated oracle lane (`book/evidence/experiments/runtime-closure/out/0c49afaa-0739-4239-9275-eb875c6232da/runtime_events.normalized.json`).

## Seatbelt interfaces summary (Seatbelt_Interfaces.md)
The seatbelt interface map is documented in `book/evidence/experiments/runtime-closure/Seatbelt_Interfaces.md` and explains how SBPL compilation/apply, operation-stage enforcement, oracle callouts, and observer logs are classified. It anchors the apply-gate boundary for `iokit-external-method` (same apply-gate run as above) and records the op vocabulary drift warning (`book/evidence/experiments/runtime-closure/out/7deb2296-7fa8-48ea-849f-ac7a696f7c93/77c3c910-25d5-4499-9e5e-c70c570597ff/runtime_results.json`) as an interface-level signal, not a policy decision.

## Lanes

### File canonicalization
Profiles test alias (`/etc` + `/tmp`), private, and Data spellings as literal-only rules for `/etc/hosts` and `/tmp/foo`. The goal is to separate spelling and firmlink effects from policy outcomes.

Observed (run: `out/ea704c9c-5102-473a-b942-e24af4136cc8/`):
- Alias profile (`v2_alias_literals`) denies all six probes at operation stage.
- Private profile (`v2_private_literals`) allows `/private/etc/hosts`, `/System/Volumes/Data/private/etc/hosts`, `/private/tmp/foo`, `/System/Volumes/Data/private/tmp/foo`, and `/tmp/foo`; `/etc/hosts` remains denied.
- Data profile (`v2_data_literals`) denies all six probes, including the Data spellings, at operation stage.
- `path_witnesses.json` baseline shows `/etc/hosts` -> `/private/etc/hosts` and `/tmp/foo` -> `/private/tmp/foo`. Scenario successes report `F_GETPATH_NOFIRMLINK:/System/Volumes/Data/private/...` for the private profile.
All three profiles compile and apply successfully (`sandbox_init` rc=0); failures are operation-stage (`failure_stage: probe`).
Oracle calibration (runs: `out/fe3745a4-1049-4a17-8246-0a29e5585d0e/`, `out/0c49afaa-0739-4239-9275-eb875c6232da/`, `out/77d63a7c-1d11-4dee-870c-4e745014189e/`) shows `sandbox_check` callouts returning `deny` for every `file-read-data` target, including a precreated `/private/tmp/sandbox-lore-oracle.txt` under an allow rule; the file oracle lane does not flip with SBPL allows on this host and is treated as blocked evidence.

Interpretation (bounded):
- `/tmp/foo` fits the “alias fails, private succeeds” bucket: the private literal rule allows alias and Data spellings, suggesting canonicalization to `/private/tmp` at operation time.
- `/etc/hosts` remains unresolved: private spelling allows `/private/etc/hosts` and Data spellings, but the alias spelling (`/etc/hosts`) still denies.

### Mach service discrimination
One profile allows `mach-lookup` for a known service and a missing control name. Baseline vs scenario outcomes distinguish “missing service” from “sandbox denial.”

Observed (run: `out/66315539-a0ce-44bf-bff0-07a79f205fea/`):
- `com.apple.cfprefsd.agent` allowed in baseline and scenario (`kr=0`).
- `com.apple.sandbox-lore.missing` returns `kr=1102` in baseline and scenario (missing service), so the “deny” result is not a sandbox decision on this host.
Oracle calibration (run: `out/77d63a7c-1d11-4dee-870c-4e745014189e/`) shows `sandbox_check` denying `mach-lookup` for both services even when `bootstrap_look_up` succeeds for `com.apple.cfprefsd.agent`, so oracle results are not used as a gating signal.

### IOKit
Profiles target IOSurfaceRoot via user-client-class filters to align with anchor-level structure.

Observed (runs: `out/6ecc929d-fec5-4206-a85c-e3e265c349a7/`, `out/08887f36-f87b-45ff-8e9e-6ee7eb9cb635/`, `out/33ff5a68-262a-4a8c-b427-c7cb923a3adc/`, `out/fae371c2-f2f5-470f-b672-cf0c3e24d6c0/`, `out/bf996c2f-a265-4bb5-8c8a-105bd70af25a/`, `out/03aaad16-f06b-4ec7-a468-c6379abbeb4d/`, `out/ad767bba-9e59-40ff-b006-45fe911b2d02/`, `out/760494b1-5088-4271-ba05-50c3888c8690/`, `out/7edc2b2f-7edf-4a50-ba0c-bd9bb2a549d3/`, `out/7deb2296-7fa8-48ea-849f-ac7a696f7c93/`, `out/e32f5fe4-c074-4398-9696-0807ef7fbc00/`):
- `v2_user_client_only` (`iokit-open-user-client`) allows `IOSurfaceRoot` (`open_kr=0`) at operation stage.
- `v4_iokit_open_user_client` (`iokit-open`) allows `IOSurfaceRoot` (`open_kr=0`) at operation stage.
- `v3_connection_user_client` denies with `open_kr=-536870174` and `EPERM` at operation stage.
- `v5_service_only` (`iokit-open-service` allow + user-client deny) returns `open_kr=-536870174` (EPERM), `surface_create_ok=false`.
- `v6_user_client_only` (`iokit-open-user-client` allow + service deny) returns `open_kr=-536870174` (EPERM), `surface_create_ok=false`.
- `v7_service_user_client_both` (allow both ops) returns `open_kr=0` with `call_kr=-536870206`, `call_kr_string="(iokit/common) invalid argument"`, selector=9, and all call input/output sizes zero; `surface_create_ok=false`.
- `v12_service_user_client_cvmsserv` (allow both ops + `mach-lookup com.apple.cvmsServ`) returns `open_kr=0` with the same `call_kr=-536870206` and `surface_create_ok=false`, so the cvmsServ allow does not flip the post-open failure on this host.
- `v13_ioaccelerator_connection`, `v14_iosurface_send_right`, and `v15_ioacceleration_user_client` each keep `open_kr=0` but leave `call_kr=-536870206` and `surface_create_ok=false`, so these single-delta graphics expansions do not change the post-open failure on this host.
- Oracle-only A/B/C alignment run (`v16_service_only_registry`, `v17_user_client_registry`, `v18_service_user_client_registry`) uses registry-entry-class predicates for the oracle lane and skips IOServiceOpen/post-open actions. The oracle callouts still report `iokit-open-user-client` deny across all three profiles, including the user-client-only profile, so the oracle truth table does not align with the SBPL allow rules on this host.
- `v8_external_method` (allow open + external-method) fails at apply stage with `sandbox_init` error `iokit-external-method operation not applicable in this context` and is treated as blocked evidence.
- `v9_message_filter_deny` and `v10_message_filter_allow` are blocked at preflight (`likely_apply_gated_for_harness_identity`) due to the deny-style message filter inside `apply-message-filter`, so no runtime probe execution occurs.

Call-shape instrumentation:
- A DYLD interposer (`harness/iokit_call_interpose.c`) crashes when injected into `iokit_probe` or `iosurface_trace` (SIGSEGV, no output).
- The dynamic-interpose `iosurface_trace` run (`out/iosurface_call_trace/iosurface_trace_stderr.txt`) reports the IOSurface and IOKit images and successful install, but emits no `SBL_IKIT_CALL` lines, so no selector/argument shape was observed for `IOSurfaceCreate` on this host.
- In-probe interpose capture (`SANDBOX_LORE_IKIT_CAPTURE_CALLS=1`) with IOConnectCall* + MIG stub hooks (`out/518f2e1d-66db-4392-89e8-4a74db154a82/`) reports `surface_create_ok=true` but `capture_seen=false`, so no selector/shape is observable in-process for `IOSurfaceCreate` on this host.
- Synthetic capture control (`out/df0d8269-e0fb-4306-b942-74853239c60b/`) forces an IOConnectCallMethod via `dlsym`, yielding `capture_seen=true` with selector 0 and non-zero sizes; capture plumbing now has a positive hit.
- Capture → replay loop:
  - Baseline capture run `out/274a4c71-3c97-4aaa-a22f-93b587ba9ba9/` (launchd_clean, `SANDBOX_LORE_IKIT_SELECTOR_LIST=0`) records `capture_first_spec="IOConnectCallMethod:0:1:16:0:16"` with `call_kr=-536870206` at operation stage and `surface_create_ok=true` in baseline.
  - Replay run `out/e720b256-2f6e-4888-9288-2e19b5007fa9/` (launchd_clean, `SANDBOX_LORE_IKIT_REPLAY=1`, `SANDBOX_LORE_IKIT_REPLAY_SPEC=IOConnectCallMethod:0:1:16:0:16`) replays the tuple under sandbox and returns `replay_kr=-536870206` in both baseline and scenario, with `replay_attempted=true` and no selector sweep (replay mode).
  - Interpretation: the captured post-open call shape is invalid in baseline and sandbox, so the IOSurface post-open failure is a call-shape issue, not a sandbox gate, at hypothesis tier.
All profiles apply successfully (`sandbox_init` rc=0). The post-open selector sweep still returns `call_kr=-536870206` under all scenarios, while `IOSurfaceCreate` succeeds unsandboxed (`surface_create_ok=true` in `book/api/runtime/native/probes/iokit_probe IOSurfaceRoot`) and fails under the sandbox, so Action B is now a discriminating failure signal but does not yet surface an op-name witness.

This indicates the user-client-class filter is sufficient for the IOSurfaceRoot probe, while the IOAccelerator connection constraint is too narrow on this host.

Op-witness attempts:
- Report-loud `v11_report_loud` (deny default + telemetry) kills `sandbox_iokit_probe` at probe stage (`exit_code=-5`, SIGTRAP), producing no stdout/stderr and no sandbox log lines; log capture in `out/bf200589-b801-4771-8b73-a84dfef73be6/observer/sandbox_log.txt` contains only the filter header.
- Oracle lane callouts enabled on `v7_service_user_client_both` (`out/6ed9e0b6-a2cf-4122-846e-c9c36eea52a0/`) emit `sandbox_check_by_audit_token` markers: `iokit-open-service` allows with filter `iokit-registry-entry-class` + `IOSurfaceRoot`, while `iokit-open-user-client` with filter `iokit-user-client-type` + `IOSurfaceRootUserClient` returns `EINVAL` (`rc=-1`), so the user-client callout shape remains invalid on this host.
- Oracle lane callouts expanded in `v12_service_user_client_cvmsserv` (`out/760494b1-5088-4271-ba05-50c3888c8690/`) show `iokit-open` + `iokit-registry-entry-class` denies (`rc=1`, `errno=1`) and emits a sandbox warning that `iokit-open` is obsolete, while `iokit-open-service` + `iokit-registry-entry-class` allows (`rc=0`). `iokit-open-user-client` remains `EINVAL` for both string and numeric user-client-type arguments, so the oracle lane still cannot validate that op on this host.
- Oracle lane callouts tightened via `iokit-registry-entry-class` in `v7_service_user_client_both` (`out/7edc2b2f-7edf-4a50-ba0c-bd9bb2a549d3/`) now return a real deny (`rc=1`, `errno=0`) for `iokit-open-user-client` when queried with `IOSurfaceRootUserClient` (and `IOSurfaceRoot`). This removes the EINVAL-only failure mode for that op, while `iokit-open-user-client` with `iokit-connection` still returns an error (`errno=3`) and `iokit-user-client-type` remains `EINVAL`.
- Oracle-only A/B/C (`out/e32f5fe4-c074-4398-9696-0807ef7fbc00/`) confirms the registry-entry-class oracle callout is stable (no EINVAL), but it does not reflect SBPL allow outcomes for `iokit-open-user-client`, so the oracle lane remains a blocked discriminator for op identity on this host.

## Evidence & artifacts
- Runtime plan/registry: `book/evidence/experiments/runtime-closure/plan.json` and `registry/{probes.json,profiles.json}`.
- SBPL profiles: `book/evidence/experiments/runtime-closure/sb/*.sb`.
- Run bundles: `book/evidence/experiments/runtime-closure/out/<run_id>/`.
  - File lane (v2 matrix): `book/evidence/experiments/runtime-closure/out/ea704c9c-5102-473a-b942-e24af4136cc8/` (includes `path_witnesses.json` and `promotion_packet.json`).
  - File oracle calibration: `book/evidence/experiments/runtime-closure/out/fe3745a4-1049-4a17-8246-0a29e5585d0e/`, `book/evidence/experiments/runtime-closure/out/0c49afaa-0739-4239-9275-eb875c6232da/` (callouts deny all file targets).
  - Mach lane: `book/evidence/experiments/runtime-closure/out/66315539-a0ce-44bf-bff0-07a79f205fea/`.
  - IOKit op-identity lane: `book/evidence/experiments/runtime-closure/out/6ecc929d-fec5-4206-a85c-e3e265c349a7/`, `book/evidence/experiments/runtime-closure/out/08887f36-f87b-45ff-8e9e-6ee7eb9cb635/`, `book/evidence/experiments/runtime-closure/out/33ff5a68-262a-4a8c-b427-c7cb923a3adc/`, `book/evidence/experiments/runtime-closure/out/fae371c2-f2f5-470f-b672-cf0c3e24d6c0/`, `book/evidence/experiments/runtime-closure/out/bf996c2f-a265-4bb5-8c8a-105bd70af25a/`, `book/evidence/experiments/runtime-closure/out/03aaad16-f06b-4ec7-a468-c6379abbeb4d/`, `book/evidence/experiments/runtime-closure/out/ad767bba-9e59-40ff-b006-45fe911b2d02/`, `book/evidence/experiments/runtime-closure/out/bf200589-b801-4771-8b73-a84dfef73be6/`, `book/evidence/experiments/runtime-closure/out/f7b0ca74-c80b-4431-b0bc-9f1c97962e82/`, `book/evidence/experiments/runtime-closure/out/6ed9e0b6-a2cf-4122-846e-c9c36eea52a0/`, `book/evidence/experiments/runtime-closure/out/760494b1-5088-4271-ba05-50c3888c8690/`, `book/evidence/experiments/runtime-closure/out/7edc2b2f-7edf-4a50-ba0c-bd9bb2a549d3/`, `book/evidence/experiments/runtime-closure/out/7deb2296-7fa8-48ea-849f-ac7a696f7c93/`, `book/evidence/experiments/runtime-closure/out/518f2e1d-66db-4392-89e8-4a74db154a82/`, `book/evidence/experiments/runtime-closure/out/274a4c71-3c97-4aaa-a22f-93b587ba9ba9/`, `book/evidence/experiments/runtime-closure/out/e720b256-2f6e-4888-9288-2e19b5007fa9/`.
- Call-shape trace: `book/evidence/experiments/runtime-closure/out/iosurface_call_trace/iosurface_trace_stderr.txt`, `book/evidence/experiments/runtime-closure/out/iosurface_call_trace/iosurface_trace_stdout.txt`, `book/evidence/experiments/runtime-closure/out/iosurface_call_trace_2/iosurface_trace_stderr.txt`, `book/evidence/experiments/runtime-closure/out/iosurface_call_trace_2/iosurface_trace_stdout.txt`.
  - Selector discovery (baseline): `book/evidence/experiments/runtime-closure/out/a6e042e5-135d-4072-b0d6-50455abc62a3/iokit_probe_stdout.txt` and `book/evidence/experiments/runtime-closure/out/a6e042e5-135d-4072-b0d6-50455abc62a3/iokit_probe_stderr.txt` using a WebKit-derived candidate list with non-zero call shapes.
  - Observer-lane logs: `book/evidence/experiments/runtime-closure/out/bf996c2f-a265-4bb5-8c8a-105bd70af25a/observer/sandbox_log_stream_iokit.txt` and `book/evidence/experiments/runtime-closure/out/bf996c2f-a265-4bb5-8c8a-105bd70af25a/observer/sandbox_log_show_iokit.txt` (no iokit op lines observed).
  - Prior runs: `book/evidence/experiments/runtime-closure/out/5a8908d8-d626-4cac-8bdd-0f53c02af8fe/` (file v1) and `book/evidence/experiments/runtime-closure/out/48086066-bfa2-44bb-877c-62dd1dceca09/` (IOKit v1).
- Mapped VFS update: `book/integration/carton/bundle/relationships/mappings/vfs_canonicalization/path_canonicalization_map.json` (now includes the runtime-closure file matrix packet).

## Limitations
- Apply-stage gating is blocked evidence; failures at apply/exec are not policy outcomes.
- Missing services/classes are not denials and must be resolved via baseline lane.
- `/etc/hosts` remains unresolved when spelled as `/etc/...` even when private and Data spellings are allowed.
- Data-only literal rules do not allow Data spellings on this host, suggesting enforcement compares a different spelling; this remains hypothesis-level without a direct kernel witness at operation time.
- `with report` is not accepted on deny rules in this harness, so the initial tri-matrix attempt (`out/1034a7bd-81e1-41a1-9897-35f5556800c7/`) failed at apply stage and is treated as blocked evidence.
- `iokit-external-method` is rejected at apply stage for the IOSurface user-client rule in this harness (`out/03aaad16-f06b-4ec7-a468-c6379abbeb4d/`), and deny-style message filters trigger preflight apply-gate blocks (`out/ad767bba-9e59-40ff-b006-45fe911b2d02/`), so external-method gating remains blocked on this host.
- The report-loud `v11_report_loud` profile terminates the probe (SIGTRAP), so sandbox log capture via deny-default telemetry did not yield an op witness on this host.
- Oracle-lane `sandbox_check_by_audit_token` succeeds for `iokit-open-service` but returns `EINVAL` for `iokit-open-user-client` with the current filter/argument shape, so user-client callouts remain hypothesis-only until the filter tuple is corrected.
