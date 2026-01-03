# IOKit lane reference (runtime-closure)

## Purpose and scope

This document is the durable, host-scoped record of the IOKit lane in runtime-closure for world_id `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`. The lane is focused on stage-labeled runtime evidence, not on claiming sandbox policy semantics. In particular, the current post-open IOSurface work is still a call-shape/interface problem: the best candidate calls return `kIOReturnBadArgument` in both baseline and sandbox, so no sandbox gate claim is supported yet.

## Evidence model used

Evidence scope:
- Shared mappings: vocab and baseline contracts (not modified here)
- Structural bindings already promoted for IOSurfaceRootUserClient via delta attribution
- Runtime outcomes and instrumentation-derived signals recorded as observations
- Apply/compile/preflight failures or inapplicable constructs are marked `blocked`

Runtime stage taxonomy:
- compile: SBPL source to blob
- apply: sandbox_init/sandbox_apply
- exec: probe process runs and emits JSON
- operation: actual IOKit action result (IOReturn/errno)

Runtime lanes used:
- baseline: unsandboxed `iokit_probe`
- scenario: sandboxed `sandbox_iokit_probe`
- oracle: sandbox_check* callouts (kept as annotations until calibrated)

## Current outcomes (summary)

- IOServiceOpen succeeds under the working v7 profile (`open_kr=0`), but post-open work remains blocked by call-shape mismatch. Operation-stage failures are `kIOReturnBadArgument` in both baseline and sandbox.
- Method-0 create payload attempts (IOCFSerialize XML and binary) are still invalid-argument at operation stage.
- A bounded selector sweep (0..25 with create-props payload) produced no non-invalid tuple.
- Mach message capture filtered by the user-client port remains empty even with synthetic IOConnectCallMethod activity, so the mach capture sensor is not yet validated on this host.

## IOKit lane runs that matter

| Evidence pointer | Profile / mode | Compile | Apply | Exec | open_kr | call_kr | surface_create_ok | Payload format | Capture / replay fields | Interpretation |
|---|---|---|---|---|---:|---:|---|---|---|---|
| `book/evidence/experiments/runtime-final-final/suites/runtime-closure/out/iosurface_method0_sweep.json` | baseline `iokit_probe` (method0 sweep 0..25) | n/a | n/a | ok | 0 | -536870206 | true | iocf_xml | `sweep_results`, `first_non_invalid_missing=true` | Call-shape mismatch; no non-invalid selector found. |
| `book/evidence/experiments/runtime-final-final/suites/runtime-closure/out/iosurface_method0_binary.json` | baseline `iokit_probe` (method0 binary) | n/a | n/a | ok | 0 | -536870206 | true | iocf_binary | none | Call-shape mismatch persists under binary IOCFSerialize. |
| `book/evidence/experiments/runtime-final-final/suites/runtime-closure/out/iosurface_mach_capture.json` | baseline `iokit_probe` (mach capture) | n/a | n/a | ok | 0 | n/a | true | n/a | `mach_msg_capture_count=0` | Mach capture sensor still unvalidated on this host. |
| `book/evidence/experiments/runtime-final-final/suites/runtime-closure/out/iosurface_mach_capture_synth.json` | baseline `iokit_probe` (mach capture + synthetic call) | n/a | n/a | ok | 0 | n/a | true | n/a | `synthetic_call_attempted=true`, `mach_msg_capture_count=0` | Synthetic call did not yield mach capture events. |
| `book/evidence/experiments/runtime-final-final/suites/runtime-closure/out/274a4c71-3c97-4aaa-a22f-93b587ba9ba9/runtime_events.normalized.json` | v19_capture_replay (capture tuple under sandbox) | n/a | ok | ok | 0 | -536870206 | false | n/a | replay disabled; call_kr invalid | Captured tuple is invalid at operation stage. |
| `book/evidence/experiments/runtime-final-final/suites/runtime-closure/out/e720b256-2f6e-4888-9288-2e19b5007fa9/runtime_events.normalized.json` | v19_capture_replay (replay tuple under sandbox) | n/a | ok | ok | 0 | n/a | false | n/a | `replay_attempted=true`, `replay_kr=-536870206` | Replay confirms invalid tuple in sandbox. |
| `book/evidence/experiments/runtime-final-final/suites/runtime-closure/out/289b183e-d86e-47db-ae57-0b9bd3541c6a/runtime_events.normalized.json` | v7_service_user_client_both (method0 payload file) | n/a | ok | ok | 0 | -536870206 | false | file | method0 fields present, no replay | Same invalid-argument result under sandbox; not a gate claim. |
| `book/evidence/experiments/runtime-final-final/suites/runtime-closure/out/03aaad16-f06b-4ec7-a468-c6379abbeb4d/mismatch_summary.json` | v8_external_method (apply-message-filter) | n/a | blocked | n/a | n/a | n/a | n/a | n/a | apply_gate | iokit-external-method not applicable in this context. |

## Tooling inventory (runtime-closure IOKit)

| Env toggle | Consumed by | Effect | Key output fields |
|---|---|---|---|
| `SANDBOX_LORE_IKIT_METHOD0=1` | `iokit_probe`, `sandbox_iokit_probe` | selector-0 struct method using serialized create props | `method0_*`, `call_kr`, `call_selector` |
| `SANDBOX_LORE_IKIT_METHOD0_BINARY=1` | both probes | use IOCFSerialize binary | `method0_plist_format=iocf_binary` |
| `SANDBOX_LORE_IKIT_SWEEP=1` | `iokit_probe` | bounded sweep; with method0 uses create payload and selectors 0..25 | `sweep_results`, `first_non_invalid_*` |
| `SANDBOX_LORE_IKIT_MACH_CAPTURE=1` | `iokit_probe`, `sandbox_iokit_probe` | interpose mach_msg and trap-level entrypoints | `mach_msg_capture_count`, `mach_msg_capture` |
| `SANDBOX_LORE_IKIT_CAPTURE_CALLS=1` | `iokit_probe` | record first interposed IOConnectCall* | `capture_first_*`, `capture_*` |
| `SANDBOX_LORE_IKIT_REPLAY=1` + `SANDBOX_LORE_IKIT_REPLAY_SPEC` | both probes | replay a captured tuple | `replay_*` |
| `SANDBOX_LORE_IKIT_METHOD0_PAYLOAD_IN` / `..._OUT` | both probes | load/write serialized payload | `method0_payload_source`, `method0_input_bytes` |
| `SANDBOX_LORE_IKIT_SYNTH_CALL=1` | `iokit_probe` | synthetic IOConnectCallMethod to validate capture | `synthetic_call_*` |

Env forwarding for launchd_clean is documented in `book/api/runtime/execution/channels/launchd_clean.py` (method0 payload envs are forwarded, and sandbox probe preloads payload before apply).

## Method-0 create attempt timeline (bounded)

1) Baseline IOCFSerialize XML create-props payload with selector 0 and output size 0x2000 still returns invalid argument.
2) Bounded selector sweep 0..25 with the same payload returns invalid argument for all selectors.
3) IOCFSerialize binary toggled for selector 0 still returns invalid argument.

These steps keep the conclusion tightly scoped: the current call shape is still wrong on this host, so post-open failure is not yet a sandbox gate claim.

## Boundaries and host-specific constraints

- apply-message-filter / iokit-method-number rules are apply-gated for this harness identity (blocked frontier; see `book/evidence/experiments/runtime-final-final/suites/runtime-closure/out/03aaad16-f06b-4ec7-a468-c6379abbeb4d/mismatch_summary.json`).
- sandbox_check oracle lanes are uncalibrated for file ops and IOKit filters; treat callouts as annotations only.
- mach_msg capture filtered by the io_connect_t port is still unvalidated; a positive-control mach send is required before interpreting zero counts.

## Selected excerpts (verbatim)

Method-0 selector sweep, no non-invalid tuple:
```json
// book/evidence/experiments/runtime-final-final/suites/runtime-closure/out/iosurface_method0_sweep.json
{"call_kr":-536870206,"call_kr_string":"(iokit/common) invalid argument","method0_plist_format":"iocf_xml","method0_input_bytes":368,"sweep_result_count":26,"first_non_invalid_missing":true}
```

Binary method-0 attempt still invalid:
```json
// book/evidence/experiments/runtime-final-final/suites/runtime-closure/out/iosurface_method0_binary.json
{"call_kr":-536870206,"method0_plist_format":"iocf_binary","method0_input_bytes":209,"method0_payload_nul_appended":true}
```

Sandboxed v7 run with method-0 payload file:
```json
// book/evidence/experiments/runtime-final-final/suites/runtime-closure/out/289b183e-d86e-47db-ae57-0b9bd3541c6a/runtime_events.normalized.json
{"call_kr":-536870206,"call_kr_string":"(iokit/common) invalid argument","open_kr":0,"surface_create_ok":false,"method0_plist_format":"file","method0_input_bytes":368}
```

IOCFSerialize usage in the probe:
```c
// book/api/runtime/native/probes/iokit_probe.c
CFDataRef data = IOCFSerialize(props, serialize_flags);
if (data && format_out) {
    *format_out = (serialize_flags & kIOCFSerializeToBinary) ? "iocf_binary" : "iocf_xml";
}
```
