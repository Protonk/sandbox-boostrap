# gate-witnesses

## Purpose

Produce a **durable witness corpus** for “apply-stage `EPERM`” on this host baseline and wire it into validation so the boundary stays stable across refactors of wrappers/runners/contracts.

This experiment is intentionally narrow:
- It does **not** claim that any particular Operation+Filter was denied by a PolicyGraph.
- It treats apply-stage `EPERM` as **hypothesis evidence** (the Profile never attached), consistent with the EPERM phase discipline in [`troubles/EPERMx2.md`](../../../troubles/EPERMx2.md).

## Baseline & scope

- World: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`
- Apply surface: `book/tools/sbpl/wrapper/wrapper --sbpl … -- /usr/bin/true`
- Classification: runtime contract layer (`book/api/runtime/contracts/schema.py`) + `sbpl-apply` tool markers (no stderr substring inference)
- Recent witness refresh runs were executed on both a permissive host configuration (`--yolo`) and a less permissive control pass; the snapshots are preserved as `out/witnesses/airlock/run.yolo.json` and `out/witnesses/airlock/run.non_yolo.json` (current `run.json` matches the permissive run).

## Artifacts

Checked-in outputs live under:

- `out/witnesses/<target>/minimal_failing.sb`
- `out/witnesses/<target>/passing_neighbor.sb`
- `out/witnesses/<target>/run.json`
- `out/witnesses/<target>/run.yolo.json` and `out/witnesses/<target>/run.non_yolo.json` (context snapshots)
- `out/witnesses/<target>/trace.jsonl`

Derived-only summaries:
- `out/feature_summary.json`
- `out/clusters.json`
- `out/compile_vs_apply.json` (compile-vs-apply fork + micro-variant matrix)
- `out/micro_variants/*.sb` (stable SBPL inputs for the micro-variant matrix)
- `out/entitlements_scan.json` (codesign scan for message-filter-related entitlements)
- `out/message_filter_xrefs.json` (xref summary for message-filter strings in sandbox_kext + userland string presence)

## Current corpus (confirmed)

The current witness corpus includes:

- `airlock` (source: `/System/Library/Sandbox/Profiles/airlock.sb`)
- `blastdoor` (source: `/System/Library/Sandbox/Profiles/blastdoor.sb`)
- `com.apple.CoreGraphics.CGPDFService` (source: `/System/Library/Sandbox/Profiles/com.apple.CoreGraphics.CGPDFService.sb`)
- `mach_bootstrap_deny_message_send` (source: `out/micro_variants/base_v2_mach_bootstrap_deny_message_send.sb`)

The system-profile cluster delta-debug down to the same minimal failing construct:

- `(allow iokit-open-user-client (apply-message-filter (deny iokit-external-method)))`

The non-IOKit witness delta-debugs down to:

- `(allow mach-bootstrap (apply-message-filter (deny mach-message-send)))`

The `--confirm 10` runs are now split by host context:
- Permissive host (`--yolo`): `airlock` confirms apply-stage `EPERM` and a passing neighbor (`confirm.passing_neighbor` present). See `book/evidence/experiments/runtime-final-final/suites/gate-witnesses/out/witnesses/airlock/run.yolo.json` (current `run.json`).
- Less permissive control pass: `airlock` still confirms apply-stage `EPERM`, but the minimizer could not confirm a passing neighbor (`confirm.passing_neighbor` is null). See `book/evidence/experiments/runtime-final-final/suites/gate-witnesses/out/witnesses/airlock/run.non_yolo.json`.

We don’t know yet whether the passing neighbor remains non-gated outside this global-gate context; treat the discrepancy as bounded by the artifacts above.

## Compile-vs-apply fork (where is the gate enforced?)

This repo previously treated the witness predicate as “`sandbox_init` fails with `EPERM`”, which does not, by itself, distinguish *compile* failure from *apply/attach* failure because `sandbox_init` is a combined path.

To answer that fork, we run the witness pair through the explicit split:

- compile: `sandbox_compile_file` (tool marker `tool:"sbpl-compile"`)
- apply: `sandbox_apply` on the compiled blob (tool marker `tool:"sbpl-apply"` with `api:"sandbox_apply"`)

Results (see `out/compile_vs_apply.json`):

- For all three minimal failing witnesses, compilation succeeds (`rc==0`), but apply fails at `sandbox_apply` with apply-stage `EPERM` (`failure_stage=="apply"`, `apply_report.api=="sandbox_apply"`, `apply_report.errno==EPERM`).
- Therefore, **on this world**, the observed gate is **not** enforced by the user-space compiler rejecting the SBPL form at compile time; it is enforced at **apply time** (the attach/validation step reached by `sandbox_apply`).

This is still “mapped” runtime evidence: it is a repeated, mechanical observation on this host baseline, but it does not yet identify the specific kernel-side validator or process attribute gate responsible.
The compile→apply split is re-verified in the permissive (`--yolo`) context, but not in the less permissive control context.

## Micro-variant matrix (tightening the trigger within the minimized form)

We generated a small set of “one edit per run” micro-variants under `out/micro_variants/` and exercised the same compile→apply split (results recorded in `out/compile_vs_apply.json`).

Key observations from that matrix:

- For both `(version 1)` and `(version 2)` forms, the **deny** variants remain apply-gated when the message-filter payload denies any of:
  - `iokit-external-method`
  - `iokit-async-external-method`
  - `iokit-external-trap`
- Switching the inner message-filter payload from `(deny …)` to `(allow …)` avoids the apply gate on this world (apply succeeds; downstream bootstrap outcomes vary).
- The requested “swap outer op to `iokit-open`” is only meaningful for the `(version 1)` variant: in `(version 2)` it is a compiler error (`unbound variable: iokit-open`), consistent with the Operation vocabulary map for this world (`book/evidence/graph/mappings/vocab/ops.json` includes `iokit-open*` but not `iokit-open`).

Taken together, these micro-variants suggest the gate is more tightly keyed than “`apply-message-filter` exists”: on this host, “message filter that denies external-method/trap operations” appears sufficient to trigger the apply-stage gate, while “message filter that allows” does not.

## Unified log enforcement trace (runtime witness; partial)

The gate-witnesses validation job (`experiment:gate-witnesses`) captures unified logs around the explicit blob apply (`sandbox_apply`) of both the minimal failing and passing neighbor blobs.

On this world, for all current witnesses (including the non-IOKit `mach-bootstrap` deny witness), the minimal failing blob apply emits a kernel sandbox log line with a direct reason:

- `missing message filter entitlement`

Example forensics artifacts:
- minimal failing: `book/evidence/graph/concepts/validation/out/experiments/gate-witnesses/forensics/airlock/log_show_primary.minimal_failing.txt`
- passing neighbor (control window; empty): `book/evidence/graph/concepts/validation/out/experiments/gate-witnesses/forensics/airlock/log_show_primary.passing_neighbor.txt`

This is a host-grounded runtime witness: it does not rely on substring inference from wrapper stderr, and it is correlated to the wrapper PID and a bounded log window.

## Effective entitlement check marker (runtime correlation; partial)

`book/tools/sbpl/wrapper/wrapper` emits a `tool:"entitlement-check"` marker before attempting any apply, recording the runtime-effective value of `com.apple.private.security.message-filter` for the applying process.

In the gate-witnesses validation output, the blob-apply records show `present:false` for this entitlement on the wrapper process, aligning with the unified-log message above (see `entitlement_checks` in `book/evidence/graph/concepts/validation/out/experiments/gate-witnesses/witness_results.json`).

## Supporting (brittle) static clue

The kernel string inventory contains messages that are consistent with an entitlement-gated “message filter” feature (e.g. “missing message filter entitlement”), under `book/evidence/experiments/kernel-symbols/out/14.4.1-23E224/kernel-symbols/strings.json`. This is a **brittle** clue (string presence is not a behavior witness), but it aligns with the apply-time enforcement observed above.

## Entitlement corroboration (codesign; partial)

As a host-grounded corroboration point for the “entitlement-gated capability” hypothesis, we scan a small set of system executables for the private entitlement key:

- `com.apple.private.security.message-filter`

Results are recorded in `out/entitlements_scan.json`. On this world baseline, multiple system services that are plausible users of message filtering carry the key (notably WebKit XPC services, BlastDoor services, and `CGPDFService`), while `book/tools/sbpl/wrapper/wrapper` does not.

This is **mapped** evidence: it establishes that the entitlement key exists on this host and is used by real, signed system processes, but it does not by itself prove that the apply-stage gate observed in this experiment is *caused* by entitlement enforcement.

## Kernel xrefs (sandbox_kext; partial)

To turn the string clue into a more actionable boundary object, we resolved references to the message-filter-related kernel strings inside `sandbox_kext.bin` using the Ghidra task `sandbox-kext-string-refs` (summary recorded in `out/message_filter_xrefs.json`).

Key xrefs on this world:
- `com.apple.private.security.message-filter` → referenced by `_syscall_set_userland_profile`
- `com.apple.private.security.message-filter-manager` → referenced by `_syscall_message_filter_{retain,release}`
- “missing message filter entitlement” → referenced by `_syscall_set_userland_profile`

This is still **mapped** evidence: it is stronger than “string exists” because it identifies concrete sandbox-kext call sites, but it is still static (not a runtime witness of why a particular `sandbox_apply` failed in our harness identity).

The same summary also records a small userland cross-check: the trimmed dyld slices under `book/evidence/graph/mappings/dyld-libs/` contain many `message-filter`-related SBPL/compiler strings, but do not contain the entitlement key strings themselves, which is consistent with a kernel-side entitlement check rather than a purely userland compiler-side gate.

## Validation

The validation job now reports `ok` in the permissive (`--yolo`) context and emits witness results. See:
- `book/evidence/graph/concepts/validation/out/experiments/gate-witnesses/status.json`
- `book/evidence/graph/concepts/validation/out/experiments/gate-witnesses/witness_results.json`

The less permissive control pass was not re-run through validation; its snapshot is preserved in `book/evidence/experiments/runtime-final-final/suites/gate-witnesses/out/witnesses/airlock/run.non_yolo.json`.

## Status

- Status: **partial**.
  - The witness corpus itself is confirmed and small (structural boundary object).
  - The *meaning* of the triggering construct (“why this causes an apply gate on this world”) remains open and is not inferred from these witnesses alone.
  - Less permissive control pass: we don’t know yet whether the passing neighbor remains non-gated outside that context; the snapshot shows `confirm.passing_neighbor` is null. See `book/evidence/experiments/runtime-final-final/suites/gate-witnesses/out/witnesses/airlock/run.non_yolo.json`.
