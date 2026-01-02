# Failures and blocked frontiers (runtime-closure)

This file is the non-narrative record of what did not move the needle on this host, with strict stage labeling. Each entry is a short attempt -> evidence pointer -> conclusion note. This preserves negative knowledge so future work stays bounded.

## Failure ledger (by category)

| Category | Attempt | Expected discriminator | Observed result | Evidence pointer | Conclusion |
|---|---|---|---|---|---|
| Call-shape discovery | Method-0 selector sweep (0..25) with IOCFSerialize create props | Find non-invalid baseline tuple | All selectors return kIOReturnBadArgument | `book/evidence/experiments/runtime-final-final/suites/runtime-closure/out/iosurface_method0_sweep.json` | Call-shape mismatch; selector sweep menu not aligned with interface. |
| Call-shape discovery | Method-0 binary IOCFSerialize (selector 0) | Non-invalid baseline call | kIOReturnBadArgument persists | `book/evidence/experiments/runtime-final-final/suites/runtime-closure/out/iosurface_method0_binary.json` | Binary vs XML does not resolve call-shape mismatch. |
| Observability | Mach capture (port-filtered) during IOSurfaceCreate | See messages to io_connect_t port | mach_msg_capture_count=0 | `book/evidence/experiments/runtime-final-final/suites/runtime-closure/out/iosurface_mach_capture.json` | Capture sensor unvalidated; does not show IOSurface path yet. |
| Observability | Mach capture with synthetic IOConnectCallMethod | Positive control for mach capture | mach_msg_capture_count=0 despite synthetic call | `book/evidence/experiments/runtime-final-final/suites/runtime-closure/out/iosurface_mach_capture_synth.json` | Trap-level interpose is not recording port sends yet. |
| SBPL expressivity | apply-message-filter / iokit-external-method rule | Apply succeeds with message filter | Apply gated (operation not applicable) | `book/evidence/experiments/runtime-final-final/suites/runtime-closure/out/03aaad16-f06b-4ec7-a468-c6379abbeb4d/mismatch_summary.json` | Blocked frontier for this harness identity. |
| Oracle lane | sandbox_check(file-read-data, /private/etc/hosts) | Oracle matches allowed operation | Oracle still denies | `book/evidence/experiments/runtime-final-final/suites/runtime-closure/out/0c49afaa-0739-4239-9275-eb875c6232da/runtime_events.normalized.json` | Oracle lane uncalibrated; do not treat as stop-rule. |

## Excerpts (verbatim)

Method-0 sweep: all selectors invalid argument.
```json
// book/evidence/experiments/runtime-final-final/suites/runtime-closure/out/iosurface_method0_sweep.json
{"sweep_result_count":26,"first_non_invalid_missing":true,"call_kr_string":"(iokit/common) invalid argument"}
```

Binary IOCFSerialize still invalid:
```json
// book/evidence/experiments/runtime-final-final/suites/runtime-closure/out/iosurface_method0_binary.json
{"call_kr":-536870206,"method0_plist_format":"iocf_binary","method0_input_bytes":209}
```

apply-message-filter apply gate (iokit-external-method not applicable):
```text
// book/evidence/experiments/runtime-final-final/suites/runtime-closure/out/03aaad16-f06b-4ec7-a468-c6379abbeb4d/mismatch_summary.json
sandbox initialization failed: iokit-external-method operation not applicable in this context
<input string>:11:4:
	(iokit-user-client-class "IOSurfaceRootUserClient")
```

Oracle mismatch (allow in operation, deny in callout):
```json
// book/evidence/experiments/runtime-final-final/suites/runtime-closure/out/0c49afaa-0739-4239-9275-eb875c6232da/runtime_events.normalized.json
{"actual":"allow","target":"/private/etc/hosts","seatbelt_callouts":[{"operation":"file-read-data","argument":"/private/etc/hosts","rc":1,"decision":"deny"}]}
```
