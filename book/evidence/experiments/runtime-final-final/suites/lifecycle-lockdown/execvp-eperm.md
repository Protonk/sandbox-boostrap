# `execvp()` → `EPERM` after successful `sandbox_init` (lifecycle-lockdown)

Baseline: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5` (Sonoma 14.4.1 / 23E224, arm64).

This document is a self-contained, linear account of a specific failure mode observed in `book/evidence/experiments/runtime-final-final/suites/lifecycle-lockdown`: after an SBPL `(version 2)` profile is successfully applied (`sandbox_init rc=0`), the runtime runner fails to `execvp()` the intended probe with `errno=1 (EPERM)`, returning `exit_code=127` and preventing operation-stage evidence from being collected.

The evidence in this document is **bootstrap-stage** runtime evidence (`mapped`, scenario-scoped) unless explicitly stated otherwise. It is **not** a claim about sandbox semantics at operation stage.

## Quick reproduction (repo-local)

The runtime runs here are driven by `book.api.runtime` and the experiment’s runtime plan(s). The important reproducer path is `launchd_clean` (lane isolation) rather than `direct` (harness identity confounders).

```sh
# Primary plan (many profiles; historically used during exploration)
python3 -m book.api.runtime run \
  --plan book/evidence/experiments/runtime-final-final/suites/lifecycle-lockdown/plan.json \
  --channel launchd_clean \
  --out book/evidence/experiments/runtime-final-final/suites/lifecycle-lockdown/out/runtime/launchd_clean_enforce

# Focused “allow default deny scan” plan used for bootstrap narrowing
python3 -m book.api.runtime run \
  --plan book/evidence/experiments/runtime-final-final/suites/lifecycle-lockdown/plan_exec_prereq_allow_default_deny_scan.json \
  --channel launchd_clean \
  --out book/evidence/experiments/runtime-final-final/suites/lifecycle-lockdown/out/runtime/launchd_clean_enforce
```

Important harness note from `book/evidence/experiments/runtime-final-final/suites/lifecycle-lockdown/Notes.md`: in this Codex harness, `launchd_clean` required an escalated / unsandboxed invocation; otherwise `launchctl bootstrap` failed with exit status `5` (“Input/output error”).

Note: legacy runtime bundles were pruned during runtime cleanup. Rerun the plan to regenerate bundles under `out/runtime/`; the paths in the excerpts below are historical until rerun.

Representative failure excerpt (trimmed; this is before rerunning with escalation):

```text
Bootstrap failed: 5: Input/output error
Try re-running the command as root for richer errors.
...
RuntimeError: launchctl bootstrap failed: Command ['/bin/launchctl', 'bootstrap', 'gui/501', '...plist'] returned non-zero exit status 5.
```

## Glossary (as used here)

- **apply stage**: profile attachment (`sandbox_init`/`sandbox_apply`) succeeded or failed. Apply-stage `EPERM` is *hypothesis* evidence (profile didn’t attach).
- **bootstrap stage**: profile applied, but the probe did not start cleanly (e.g. `execvp()` failure). This is not operation-stage semantics.
- **operation stage**: the probe ran and attempted its action (only here can allow/deny be interpreted as policy semantics).

This issue is **bootstrap**: apply succeeds, then `execvp()` fails.

## The runner mechanism: why `exit_code=127` matters

The `launchd_clean` runtime runs use `book/api/runtime/native/sandbox_runner/sandbox_runner`, which:

1) reads the SBPL profile from a file,
2) calls `sandbox_init` (SBPL mode),
3) then `execvp()`s the target command,
4) and returns `127` when `execvp()` fails.

Relevant excerpt:

```c
// book/api/runtime/native/sandbox_runner/sandbox_runner.c
char *err = NULL;
sbl_apply_report_t report = sbl_sandbox_init_with_markers(buf, 0, &err, profile_path);
...
execvp(cmd[0], cmd);
int saved_errno = errno;
if (saved_errno == EPERM) {
    sbl_maybe_seatbelt_process_exec_callout("bootstrap_exec", cmd[0]);
}
sbl_emit_sbpl_exec_marker(-1, saved_errno, cmd[0]);
perror("execvp");
return 127;
```

So, an `exit_code=127` in this experiment is the “`execvp()` failed” path, not an operation-stage decision.

## Observability: why “no markers” can be a policy effect

The runtime tooling emits structured JSONL markers to `stderr` (tool markers are intentionally treated as inputs to normalization, not as “regular stderr text”).

Relevant excerpt:

```c
// book/api/runtime/native/tool_markers.h
static SBL_UNUSED void sbl_emit_sbpl_exec_marker(int rc, int err, const char *argv0) {
    FILE *out = stderr;
    int first = 1;
    fputc('{', out);
    sbl_json_emit_kv_string(out, &first, "tool", SANDBOX_LORE_SBPL_APPLY_TOOL);
    sbl_json_emit_kv_int(out, &first, "marker_schema_version", SANDBOX_LORE_SBPL_APPLY_MARKER_SCHEMA_VERSION);
    sbl_json_emit_kv_string(out, &first, "stage", "exec");
    sbl_json_emit_kv_int(out, &first, "rc", rc);
    sbl_json_emit_kv_int(out, &first, "errno", err);
    sbl_json_emit_kv_string(out, &first, "argv0", argv0);
    sbl_json_emit_kv_int(out, &first, "pid", (long)getpid());
    fputs("}\n", out);
    fflush(out);
}
```

If the applied profile denies writes to `stderr` (typically via `file-write-data` on `/dev/fd/*` / `/dev/stderr` semantics), the markers can disappear even when apply succeeded. This was a *real confounder* in the early runs: the system can be in the state “apply succeeded” + “marker emission denied.”

## What we observed (anchor cases)

### Case 1: markers suppressed (looks like a generic probe failure)

This is from the same `launchd_clean` bundle as later “marker-visible” failures; it differs only in whether the runtime profile allowed `file-write-data`.

When marker writes are not allowed, `stderr` is empty and the normalized failure is a generic “probe exited nonzero”:

```json
{
  "bundle_id": "d4e96281-6046-4405-81de-535fd29e8890",
  "profile_id": "lockdown:airlock_passing_sbpl",
  "exit_code": 127,
  "runtime_failure_stage": "probe",
  "runtime_failure_kind": "probe_nonzero_exit",
  "runtime_errno": 127,
  "apply_api": null,
  "preflight_classification": "no_known_apply_gate_signature",
  "stderr_head": ""
}
```

This is *observability loss*, not a different underlying mechanism.

### Case 2: markers visible → apply succeeds → `execvp()` fails with `EPERM`

Adding a broad instrumentation rule `(allow file-write-data)` makes markers visible. Then the same core failure becomes obvious:

```jsonl
{"tool":"sbpl-apply","marker_schema_version":1,"stage":"apply","mode":"sbpl","api":"sandbox_init","rc":0,"errno":0,"err_class":"ok","err_class_source":"none","profile":"/private/tmp/sandbox-lore-launchctl/sandbox-lore.runtime.d4e96281-6046-4405-81de-535fd29e8890/book/evidence/experiments/runtime-final-final/suites/lifecycle-lockdown/out/runtime/launchd_clean_enforce/d4e96281-6046-4405-81de-535fd29e8890/runtime_profiles/passing_neighbor.lockdown_airlock_passing_sbpl_write.runtime.sb","pid":5034}
{"tool":"sbpl-apply","marker_schema_version":1,"stage":"applied","mode":"sbpl","api":"sandbox_init","rc":0,"profile":"/private/tmp/sandbox-lore-launchctl/sandbox-lore.runtime.d4e96281-6046-4405-81de-535fd29e8890/book/evidence/experiments/runtime-final-final/suites/lifecycle-lockdown/out/runtime/launchd_clean_enforce/d4e96281-6046-4405-81de-535fd29e8890/runtime_profiles/passing_neighbor.lockdown_airlock_passing_sbpl_write.runtime.sb","pid":5034}
{"tool":"sbpl-apply","marker_schema_version":1,"stage":"exec","rc":-1,"errno":1,"argv0":"/private/tmp/sandbox-lore-launchctl/sandbox-lore.runtime.d4e96281-6046-4405-81de-535fd29e8890/book/api/runtime/native/file_probe/file_probe","pid":5034}
execvp: Operation not permitted
```

Normalized classification (same record family):

```json
{
  "bundle_id": "d4e96281-6046-4405-81de-535fd29e8890",
  "profile_id": "lockdown:airlock_passing_sbpl_write",
  "exit_code": 127,
  "runtime_failure_stage": "bootstrap",
  "runtime_failure_kind": "bootstrap_deny_process_exec",
  "runtime_errno": 1,
  "apply_api": "sandbox_init",
  "apply_rc": 0,
  "apply_errno": 0,
  "preflight_classification": "no_known_apply_gate_signature"
}
```

At this point we know: this is not apply gating (apply succeeded), and it is not operation-stage evidence (probe never started).

### Case 3: system-binary pivot does not avoid `execvp()` `EPERM`

To reduce “staging root” suspicions, we switched to executing a system binary: `/usr/sbin/sysctl -n kern.osrelease`.

It fails the same way (apply succeeds; exec fails with `EPERM`):

```jsonl
{"tool":"sbpl-apply","marker_schema_version":1,"stage":"apply","mode":"sbpl","api":"sandbox_init","rc":0,"errno":0,"err_class":"ok","err_class_source":"none","profile":"/private/tmp/sandbox-lore-launchctl/sandbox-lore.runtime.d4e96281-6046-4405-81de-535fd29e8890/book/evidence/experiments/runtime-final-final/suites/lifecycle-lockdown/out/runtime/launchd_clean_enforce/d4e96281-6046-4405-81de-535fd29e8890/runtime_profiles/passing_neighbor.lockdown_airlock_passing_sbpl_write_sysctl.runtime.sb","pid":5037}
{"tool":"sbpl-apply","marker_schema_version":1,"stage":"applied","mode":"sbpl","api":"sandbox_init","rc":0,"profile":"/private/tmp/sandbox-lore-launchctl/sandbox-lore.runtime.d4e96281-6046-4405-81de-535fd29e8890/book/evidence/experiments/runtime-final-final/suites/lifecycle-lockdown/out/runtime/launchd_clean_enforce/d4e96281-6046-4405-81de-535fd29e8890/runtime_profiles/passing_neighbor.lockdown_airlock_passing_sbpl_write_sysctl.runtime.sb","pid":5037}
{"tool":"sbpl-apply","marker_schema_version":1,"stage":"exec","rc":-1,"errno":1,"argv0":"/usr/sbin/sysctl","pid":5037}
execvp: Operation not permitted
```

And the normalized summary:

```json
{
  "bundle_id": "d4e96281-6046-4405-81de-535fd29e8890",
  "profile_id": "lockdown:airlock_passing_sbpl_write_sysctl",
  "exit_code": 127,
  "runtime_failure_stage": "bootstrap",
  "runtime_failure_kind": "bootstrap_deny_process_exec",
  "runtime_errno": 1,
  "apply_api": "sandbox_init",
  "apply_rc": 0
}
```

## What profiles we were actually applying (key SBPL excerpts)

The base “passing neighbor” used for this experiment is an apply-gate control profile from the gate-witness corpus:

```lisp
; book/evidence/experiments/runtime-final-final/suites/gate-witnesses/out/witnesses/airlock/passing_neighbor.sb
(version 2)
```

The runtime tool writes the effective runtime profile (base + shim + experiment-local rules) into the bundle as `runtime_profiles/*.runtime.sb`. These are the authoritative SBPL inputs for each observation.

### Failing sysctl runtime profile (no `(allow default)`)

```lisp
; .../d4e96281.../runtime_profiles/passing_neighbor.lockdown_airlock_passing_sbpl_write_sysctl.runtime.sb
(version 2)
(allow process-exec*)
(allow file-read* (subpath "/System"))
(allow file-read* (subpath "/usr"))
(allow file-read* (subpath "/bin"))
(allow file-read* (subpath "/sbin"))
(allow file-read* (subpath "/dev"))
(allow file-read-metadata (literal "/private"))
(allow file-read-metadata (literal "/private/tmp"))
(allow file-read-metadata (literal "/tmp"))
(allow file-write-data)
```

### Working sysctl runtime profile: add `(allow default)`

```lisp
; .../6629c56b.../runtime_profiles/passing_neighbor.lockdown_airlock_passing_sbpl_write_allow_default_sysctl.runtime.sb
(version 2)
(allow process-exec*)
(allow file-read* (subpath "/System"))
(allow file-read* (subpath "/usr"))
(allow file-read* (subpath "/bin"))
(allow file-read* (subpath "/sbin"))
(allow file-read* (subpath "/dev"))
(allow file-read-metadata (literal "/private"))
(allow file-read-metadata (literal "/private/tmp"))
(allow file-read-metadata (literal "/tmp"))
(allow file-write-data)
(allow default)
```

### Working profile + deny control: `(allow default)` then `(deny process-exec*)`

This is a sanity check that denies still take effect even when `default` is allowed:

```lisp
; .../52401592.../runtime_profiles/passing_neighbor.lockdown_airlock_passing_sbpl_write_allow_default_deny_process_exec_sysctl.runtime.sb
(version 2)
(allow process-exec*)
(allow file-read* (subpath "/System"))
(allow file-read* (subpath "/usr"))
(allow file-read* (subpath "/bin"))
(allow file-read* (subpath "/sbin"))
(allow file-read* (subpath "/dev"))
(allow file-read-metadata (literal "/private"))
(allow file-read-metadata (literal "/private/tmp"))
(allow file-read-metadata (literal "/tmp"))
(allow file-write-data)
(allow default)
(deny process-exec*)
```

## “Missing exec prerequisite” hunt (blind alleys / negative controls)

Once we had stable marker visibility (`file-write-data`), we tried a large set of plausible “exec prerequisites” in experiment-local profile variants (kept local in `book/evidence/experiments/runtime-final-final/suites/lifecycle-lockdown/registry/profiles.json`), rerunning via `book.api.runtime` so that:

- the applied SBPL is preserved in `runtime_profiles/`, and
- the normalized failure kind is checkable in `runtime_results.json`.

All of the following were tested **without** `(allow default)` and did **not** unblock `execvp()`; results stayed `failure_stage=bootstrap`, `errno=1 (EPERM)`, `exit_code=127`:

- `file-map-executable` (path-scoped allowlists, Preboot dyld paths, and unfiltered `(allow file-map-executable)`)
- `mach-lookup` (unfiltered)
- `mach-bootstrap` and `mach-bootstrap + mach-register`
- `file-read*` broadened all the way to unfiltered `(allow file-read*)` and separately `(allow file-read* (subpath "/private"))`
- `file-read-xattr` (unfiltered)
- `process-exec-interpreter` and `process-exec-update-label`
- `process-codesigning`
- `process-info*`
- `file-ioctl`
- `file-search`
- `file-test-existence`
- `process-exec* (subpath "/")`
- `process-exec (subpath "/")`

Representative “still blocked” bundles are enumerated in `book/evidence/experiments/runtime-final-final/suites/lifecycle-lockdown/Report.md` (sections B4/B5/B7).

The important *bounded outcome* from these blind alleys is: we did not find a narrower “just add X” substitute for `(allow default)` using only a small handful of common exec-adjacent operations.

### Representative blind alleys (verbatim SBPL + markers)

The sections below include verbatim runtime SBPL profiles (from `runtime_profiles/*.runtime.sb`) and the corresponding `stderr` marker stream (from `runtime_results.json`), to make the dead ends checkable without cross-navigation.

#### Negative control: unfiltered `file-map-executable` still fails

SBPL applied:

```lisp
; .../1bb25481-8997-4d78-9617-001f6d826fc2/runtime_profiles/..._mapexec_any_sysctl.runtime.sb
(version 2)
(allow process-exec*)
(allow file-read* (subpath "/System"))
(allow file-read* (subpath "/usr"))
(allow file-read* (subpath "/bin"))
(allow file-read* (subpath "/sbin"))
(allow file-read* (subpath "/dev"))
(allow file-read-metadata (literal "/private"))
(allow file-read-metadata (literal "/private/tmp"))
(allow file-read-metadata (literal "/tmp"))
(allow file-write-data)
(allow file-map-executable)
```

Markers:

```jsonl
{"tool":"sbpl-apply","marker_schema_version":1,"stage":"apply","mode":"sbpl","api":"sandbox_init","rc":0,"errno":0,"err_class":"ok","err_class_source":"none","profile":"/private/tmp/sandbox-lore-launchctl/sandbox-lore.runtime.1bb25481-8997-4d78-9617-001f6d826fc2/book/evidence/experiments/runtime-final-final/suites/lifecycle-lockdown/out/runtime/launchd_clean_enforce/1bb25481-8997-4d78-9617-001f6d826fc2/runtime_profiles/passing_neighbor.lockdown_airlock_passing_sbpl_write_mapexec_any_sysctl.runtime.sb","pid":15318}
{"tool":"sbpl-apply","marker_schema_version":1,"stage":"applied","mode":"sbpl","api":"sandbox_init","rc":0,"profile":"/private/tmp/sandbox-lore-launchctl/sandbox-lore.runtime.1bb25481-8997-4d78-9617-001f6d826fc2/book/evidence/experiments/runtime-final-final/suites/lifecycle-lockdown/out/runtime/launchd_clean_enforce/1bb25481-8997-4d78-9617-001f6d826fc2/runtime_profiles/passing_neighbor.lockdown_airlock_passing_sbpl_write_mapexec_any_sysctl.runtime.sb","pid":15318}
{"tool":"sbpl-apply","marker_schema_version":1,"stage":"exec","rc":-1,"errno":1,"argv0":"/usr/sbin/sysctl","pid":15318}
execvp: Operation not permitted
```

#### Negative control: unfiltered `file-read*` still fails

SBPL applied:

```lisp
; .../d759cebc-796f-4ca6-aedc-4cc2b12e270c/runtime_profiles/..._read_any_sysctl.runtime.sb
(version 2)
(allow process-exec*)
(allow file-read* (subpath "/System"))
(allow file-read* (subpath "/usr"))
(allow file-read* (subpath "/bin"))
(allow file-read* (subpath "/sbin"))
(allow file-read* (subpath "/dev"))
(allow file-read-metadata (literal "/private"))
(allow file-read-metadata (literal "/private/tmp"))
(allow file-read-metadata (literal "/tmp"))
(allow file-write-data)
(allow file-read*)
```

Markers:

```jsonl
{"tool":"sbpl-apply","marker_schema_version":1,"stage":"apply","mode":"sbpl","api":"sandbox_init","rc":0,"errno":0,"err_class":"ok","err_class_source":"none","profile":"/private/tmp/sandbox-lore-launchctl/sandbox-lore.runtime.d759cebc-796f-4ca6-aedc-4cc2b12e270c/book/evidence/experiments/runtime-final-final/suites/lifecycle-lockdown/out/runtime/launchd_clean_enforce/d759cebc-796f-4ca6-aedc-4cc2b12e270c/runtime_profiles/passing_neighbor.lockdown_airlock_passing_sbpl_write_read_any_sysctl.runtime.sb","pid":19193}
{"tool":"sbpl-apply","marker_schema_version":1,"stage":"applied","mode":"sbpl","api":"sandbox_init","rc":0,"profile":"/private/tmp/sandbox-lore-launchctl/sandbox-lore.runtime.d759cebc-796f-4ca6-aedc-4cc2b12e270c/book/evidence/experiments/runtime-final-final/suites/lifecycle-lockdown/out/runtime/launchd_clean_enforce/d759cebc-796f-4ca6-aedc-4cc2b12e270c/runtime_profiles/passing_neighbor.lockdown_airlock_passing_sbpl_write_read_any_sysctl.runtime.sb","pid":19193}
{"tool":"sbpl-apply","marker_schema_version":1,"stage":"exec","rc":-1,"errno":1,"argv0":"/usr/sbin/sysctl","pid":19193}
execvp: Operation not permitted
```

#### Negative control: unfiltered `mach-lookup` still fails

SBPL applied:

```lisp
; .../78662d76-b193-445c-a172-d770a1899f78/runtime_profiles/..._mach_lookup_sysctl.runtime.sb
(version 2)
(allow process-exec*)
(allow file-read* (subpath "/System"))
(allow file-read* (subpath "/usr"))
(allow file-read* (subpath "/bin"))
(allow file-read* (subpath "/sbin"))
(allow file-read* (subpath "/dev"))
(allow file-read-metadata (literal "/private"))
(allow file-read-metadata (literal "/private/tmp"))
(allow file-read-metadata (literal "/tmp"))
(allow file-write-data)
(allow mach-lookup)
```

Markers:

```jsonl
{"tool":"sbpl-apply","marker_schema_version":1,"stage":"apply","mode":"sbpl","api":"sandbox_init","rc":0,"errno":0,"err_class":"ok","err_class_source":"none","profile":"/private/tmp/sandbox-lore-launchctl/sandbox-lore.runtime.78662d76-b193-445c-a172-d770a1899f78/book/evidence/experiments/runtime-final-final/suites/lifecycle-lockdown/out/runtime/launchd_clean_enforce/78662d76-b193-445c-a172-d770a1899f78/runtime_profiles/passing_neighbor.lockdown_airlock_passing_sbpl_write_mach_lookup_sysctl.runtime.sb","pid":17983}
{"tool":"sbpl-apply","marker_schema_version":1,"stage":"applied","mode":"sbpl","api":"sandbox_init","rc":0,"profile":"/private/tmp/sandbox-lore-launchctl/sandbox-lore.runtime.78662d76-b193-445c-a172-d770a1899f78/book/evidence/experiments/runtime-final-final/suites/lifecycle-lockdown/out/runtime/launchd_clean_enforce/78662d76-b193-445c-a172-d770a1899f78/runtime_profiles/passing_neighbor.lockdown_airlock_passing_sbpl_write_mach_lookup_sysctl.runtime.sb","pid":17983}
{"tool":"sbpl-apply","marker_schema_version":1,"stage":"exec","rc":-1,"errno":1,"argv0":"/usr/sbin/sysctl","pid":17983}
execvp: Operation not permitted
```

#### Negative control: `file-search` still fails

SBPL applied:

```lisp
; .../2c77975f-808c-47b5-a92a-9beda16f2f1d/runtime_profiles/..._file_search_sysctl.runtime.sb
(version 2)
(allow process-exec*)
(allow file-read* (subpath "/System"))
(allow file-read* (subpath "/usr"))
(allow file-read* (subpath "/bin"))
(allow file-read* (subpath "/sbin"))
(allow file-read* (subpath "/dev"))
(allow file-read-metadata (literal "/private"))
(allow file-read-metadata (literal "/private/tmp"))
(allow file-read-metadata (literal "/tmp"))
(allow file-write-data)
(allow file-search)
```

Markers:

```jsonl
{"tool":"sbpl-apply","marker_schema_version":1,"stage":"apply","mode":"sbpl","api":"sandbox_init","rc":0,"errno":0,"err_class":"ok","err_class_source":"none","profile":"/private/tmp/sandbox-lore-launchctl/sandbox-lore.runtime.2c77975f-808c-47b5-a92a-9beda16f2f1d/book/evidence/experiments/runtime-final-final/suites/lifecycle-lockdown/out/runtime/launchd_clean_enforce/2c77975f-808c-47b5-a92a-9beda16f2f1d/runtime_profiles/passing_neighbor.lockdown_airlock_passing_sbpl_write_file_search_sysctl.runtime.sb","pid":31169}
{"tool":"sbpl-apply","marker_schema_version":1,"stage":"applied","mode":"sbpl","api":"sandbox_init","rc":0,"profile":"/private/tmp/sandbox-lore-launchctl/sandbox-lore.runtime.2c77975f-808c-47b5-a92a-9beda16f2f1d/book/evidence/experiments/runtime-final-final/suites/lifecycle-lockdown/out/runtime/launchd_clean_enforce/2c77975f-808c-47b5-a92a-9beda16f2f1d/runtime_profiles/passing_neighbor.lockdown_airlock_passing_sbpl_write_file_search_sysctl.runtime.sb","pid":31169}
{"tool":"sbpl-apply","marker_schema_version":1,"stage":"exec","rc":-1,"errno":1,"argv0":"/usr/sbin/sysctl","pid":31169}
execvp: Operation not permitted
```

## The decisive knob: `(allow default)`

Adding `(allow default)` is the first and only tested change that flips bootstrap from “cannot exec anything” to “can exec sysctl and can run the staged probe binary.”

### Sysctl succeeds under `(allow default)`

Evidence excerpt:

```json
{
  "bundle_id": "6629c56b-2729-4cc0-be08-5d3a6b7be0a2",
  "profile_id": "lockdown:airlock_passing_sbpl_write_allow_default_sysctl",
  "exit_code": 0,
  "runtime_failure_stage": null,
  "stdout_head": "23.4.0\n"
}
```

Markers (note: no `exec` marker because `execvp()` succeeded):

```jsonl
{"tool":"sbpl-apply","marker_schema_version":1,"stage":"apply","mode":"sbpl","api":"sandbox_init","rc":0,"errno":0,"err_class":"ok","err_class_source":"none","profile":"/private/tmp/sandbox-lore-launchctl/sandbox-lore.runtime.6629c56b-2729-4cc0-be08-5d3a6b7be0a2/book/evidence/experiments/runtime-final-final/suites/lifecycle-lockdown/out/runtime/launchd_clean_enforce/6629c56b-2729-4cc0-be08-5d3a6b7be0a2/runtime_profiles/passing_neighbor.lockdown_airlock_passing_sbpl_write_allow_default_sysctl.runtime.sb","pid":13569}
{"tool":"sbpl-apply","marker_schema_version":1,"stage":"applied","mode":"sbpl","api":"sandbox_init","rc":0,"profile":"/private/tmp/sandbox-lore-launchctl/sandbox-lore.runtime.6629c56b-2729-4cc0-be08-5d3a6b7be0a2/book/evidence/experiments/runtime-final-final/suites/lifecycle-lockdown/out/runtime/launchd_clean_enforce/6629c56b-2729-4cc0-be08-5d3a6b7be0a2/runtime_profiles/passing_neighbor.lockdown_airlock_passing_sbpl_write_allow_default_sysctl.runtime.sb","pid":13569}
```

### Staged `file_probe` succeeds under `(allow default)` (operation-stage evidence becomes possible)

Evidence excerpt:

```json
{
  "bundle_id": "be733a4a-1903-4028-bad7-80f07ecd18ef",
  "profile_id": "lockdown:airlock_passing_sbpl_write_allow_default_fileprobe",
  "exit_code": 0,
  "runtime_failure_stage": null,
  "stdout_head": "{\"op\":\"read\",\"path\":\"/usr/bin/true\",\"rc\":0,\"errno\":0}\n"
}
```

This is the first time the experiment produces a clean “probe executed and attempted an action” record after apply.

## Allow-default deny scan: what seems required vs not (for sysctl)

To avoid over-interpreting `(allow default)`, we built “deny scans” that start from a working allow-default profile and then selectively deny candidate operations to see what breaks.

The outcomes are bounded and concrete:

- `(deny process-exec*)` **does** reintroduce bootstrap failure (`execvp EPERM`, `exit_code=127`).
- Denying several other plausible exec-adjacent operations did **not** break `/usr/sbin/sysctl` execution in this harness (still `exit_code=0`).

Evidence excerpt (two representatives from the same deny-scan bundle):

```json
[
  {
    "bundle_id": "52401592-67fb-473e-af25-f9217d21a925",
    "profile_id": "lockdown:airlock_passing_sbpl_write_allow_default_deny_process_exec_sysctl",
    "exit_code": 127,
    "runtime_failure_stage": "bootstrap",
    "runtime_failure_kind": "bootstrap_deny_process_exec",
    "runtime_errno": 1
  },
  {
    "bundle_id": "52401592-67fb-473e-af25-f9217d21a925",
    "profile_id": "lockdown:airlock_passing_sbpl_write_allow_default_deny_file_map_executable_sysctl",
    "exit_code": 0,
    "runtime_failure_stage": null,
    "stdout_head": "23.4.0\n"
  }
]
```

Interpretation limits (important):

- This does **not** prove that `mach-lookup`, `file-map-executable`, codesigning-related operations, etc. are irrelevant to exec/dyld in general.
- It only proves that **in this observed sysctl bootstrap path**, these single denies did not prevent successful execution when `default` is allowed.

## Attempted denial logging: `(debug deny)` is rejected under SBPL `(version 2)`

We attempted to enable unified-log deny emission via SBPL `(debug deny)` so we could attribute the bootstrap `EPERM` to a specific op/filter.

On this host, under SBPL `(version 2)`, `(debug deny)` fails at apply time with an “unbound variable” error:

```text
sandbox initialization failed: unbound variable: debug at <input string>, line 12, column 2

Backtrace:
<input string>:12:2:
    debug
```

The corresponding runtime record (apply-stage failure; not semantics):

```json
{
  "bundle_id": "b8557b5d-fa11-40c5-bcb6-72cda15a61f7",
  "profile_id": "lockdown:airlock_passing_sbpl_write_debug_deny_sysctl",
  "exit_code": 1,
  "runtime_failure_stage": "apply",
  "runtime_failure_kind": "sandbox_init_failed"
}
```

## What we know / what we don’t know (current status)

What is supported by committed evidence (bootstrap, `mapped`):

1) Under this host baseline, an SBPL `(version 2)` runtime profile **without `(allow default)`** that *explicitly allows*:
   - `process-exec*`
   - `file-read*` on standard system roots
   - and instrumentation `file-write-data`
   can still fail to `execvp()` a system binary (`/usr/sbin/sysctl`) with `EPERM` after successful `sandbox_init`.

2) The same pattern holds for executing the staged probe binary (`file_probe`) under `launchd_clean`.

3) Adding `(allow default)` flips bootstrap from “`execvp()` EPERM” to “exec succeeds” for both `sysctl` and the staged `file_probe`.

4) We have not found a narrower substitute for `(allow default)` by adding a handful of likely exec-adjacent operations.

What remains unknown (open questions):

- What, precisely, is `(allow default)` doing in SBPL `(version 2)` here?
  - Is it literally “default allow” (a control directive), or is it an “operation named `default`” (the op exists in the repo’s op vocabulary), or something else?
- In the “no allow default” profile, what specific op/filter decision causes the kernel/userspace to return `EPERM` on `execve`/`execvp`?
  - We currently only see the *consequence* (`execvp` errno), not the attributed seatbelt denial record.

## Next steps (still experiment-local)

The remaining blocker is **attribution**: we need an independent witness channel that can tell us which operation/filter is being denied at bootstrap time.

Two experiment-local directions look promising:

1) Enable the existing seatbelt callout marker path in the runner:

```c
// book/api/runtime/native/tool_markers.h
static SBL_UNUSED void sbl_maybe_seatbelt_process_exec_callout(const char *stage, const char *argv0) {
    const char *enabled = getenv("SANDBOX_LORE_SEATBELT_CALLOUT");
    if (!enabled || strcmp(enabled, "1") != 0) return;
    ...
    int rc = fn(getpid(), "process-exec*", type_used, argv0);
    ...
    sbl_emit_seatbelt_callout(...);
}
```

This would let a run produce `tool:"seatbelt-callout"` markers that are independent of unified-log deny plumbing. (It requires environment plumbing so `SANDBOX_LORE_SEATBELT_CALLOUT=1` is set for the sandboxed process, and may require allowing whatever syscalls are needed to obtain audit tokens / call `sandbox_check`.)

2) Build a minimal, experiment-local variant of `sandbox_runner` that performs several `sandbox_check` callouts after `sandbox_init` (for a small set of candidate ops/filters) and emits them as markers even when `execvp` fails.

Either approach should stay inside `book/evidence/experiments/runtime-final-final/suites/lifecycle-lockdown/` until we have unambiguous attribution evidence supporting any upstream change.
