# Seatbelt interfaces (runtime-closure)

This document maps the seatbelt/sandbox interfaces touched in runtime-closure: SBPL compilation and apply, runtime enforcement ops/filters, oracle callouts, and observer/log surfaces. It is scoped to world_id `sonoma-14.4.1-23E224-arm64-dyld-a3a840f9` and is meant to prevent category errors (e.g., reading apply-stage failures as policy decisions).

## Interface map (conceptual)

```
SBPL source
  -> compile (profile blob)
  -> apply (sandbox_init / sandbox_apply)
  -> exec (probe process runs)
  -> operation (IOKit/file/mach actions)
       -> optional observers (logs)
       -> optional oracles (sandbox_check*)
```

## Stage taxonomy and lanes

Stages are recorded in runtime bundles and must be kept distinct:
- compile: SBPL source -> blob (not always exercised in baseline runs)
- apply: sandbox_init / sandbox_apply
- exec: probe process completes without crash
- operation: actual syscall/IOKit action (IOReturn/errno)

Lanes used in this experiment:
- baseline: unsandboxed probes (`iokit_probe`)
- scenario: sandboxed probes (`sandbox_iokit_probe`)
- oracle: sandbox_check* callouts (annotations unless calibrated)

## Signals and how to classify them

| Signal | Layer | Stage | Default handling | How to interpret |
|---|---|---|---|---|
| sandbox_init rc!=0 | apply | apply | blocked | Not a policy decision; profile did not attach. |
| preflight apply gate | tooling | apply | blocked | Harness boundary; do not interpret as enforcement. |
| open_kr=0 | IOKit | operation | observed | Operation succeeded under current profile. |
| call_kr=kIOReturnBadArgument | IOKit | operation | provisional | Call-shape/interface mismatch unless baseline differs. |
| oracle rc=1 | oracle | n/a | annotation-only | Annotation only until oracle calibration succeeds. |
| observer log empty | observer | n/a | no witness | No witness; do not infer deny. |

## Interfaces touched in runtime-closure

### SBPL compile/apply

SBPL is applied via `sandbox_init` in `sandbox_iokit_probe` and `sandbox_runner` tools. Apply-stage failures are treated as blocked evidence.

### Runtime enforcement ops/filters

IOKit operations and filters are used in SBPL profiles and callout probes. Several runs emitted the warning that `iokit-open` is obsolete on this host; this is recorded as an op vocabulary drift signal, not as a denial.

### Oracle lane (sandbox_check*)

The oracle lane uses sandbox_check/sandbox_check_by_audit_token and is stored in `seatbelt-callout` markers in `runtime_events.normalized.json`. This lane does not yet calibrate against known allow cases (see `Failures.md`), so it remains annotation-only.

### Observer lane (logs)

The report-loud log capture attempts can yield only the filter header; this is recorded as "no witness" rather than "no deny".

## Glossary

- op: a sandbox operation (e.g., `iokit-open-user-client`, `file-read-data`)
- filter: an op predicate (e.g., `iokit-registry-entry-class`, `path`)
- apply-gated: SBPL construct rejected at apply/preflight
- harness identity: the runtime profile + execution channel constraints that affect apply

## Excerpts (verbatim)

Apply-stage gate for iokit-external-method (blocked frontier):
```text
// book/evidence/experiments/runtime-final-final/suites/runtime-closure/out/03aaad16-f06b-4ec7-a468-c6379abbeb4d/mismatch_summary.json
sandbox initialization failed: iokit-external-method operation not applicable in this context
<input string>:11:4:
	(iokit-user-client-class "IOSurfaceRootUserClient")
```

Obsolete op warning (op vocabulary drift signal):
```text
// book/evidence/experiments/runtime-final-final/suites/runtime-closure/out/7deb2296-7fa8-48ea-849f-ac7a696f7c93/77c3c910-25d5-4499-9e5e-c70c570597ff/runtime_results.json
sandbox operation "iokit-open" is obsolete; replace with "iokit-open-user-client"
```

Oracle lane mismatch on a known-allow path:
```json
// book/evidence/experiments/runtime-final-final/suites/runtime-closure/out/0c49afaa-0739-4239-9275-eb875c6232da/runtime_events.normalized.json
{"actual":"allow","target":"/private/etc/hosts","seatbelt_callouts":[{"operation":"file-read-data","argument":"/private/etc/hosts","rc":1,"decision":"deny"}]}
```

Observer lane header only (no witness):
```text
// book/evidence/experiments/runtime-final-final/suites/runtime-closure/out/bf200589-b801-4771-8b73-a84dfef73be6/observer/sandbox_log.txt
Filtering the log data using "subsystem == "com.apple.sandbox.reporting""
```
