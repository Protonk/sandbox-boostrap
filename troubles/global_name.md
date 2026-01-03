# Global name

>New sections created below with an H2 header

## `mach-register` vs `mach-lookup`: `global-name` equivalence (AA vs AA+suffix)

claim:
  world_id: sonoma-14.4.1-23E224-arm64-dyld-2c0602c5
  status: ok
  stage: operation
  lane: scenario
  command: PYTHONPATH=. python3 -m book.api.runtime run --plan book/evidence/experiments/runtime-final-final/suites/mach-name-equivalence/plan.json --channel launchd_clean --out book/evidence/experiments/runtime-final-final/suites/mach-name-equivalence/out
  evidence:
    - book/evidence/experiments/runtime-final-final/suites/mach-name-equivalence/out/775d1303-74cf-403c-85a4-fd80cc02edde/artifact_index.json
    - book/evidence/experiments/runtime-final-final/suites/mach-name-equivalence/out/775d1303-74cf-403c-85a4-fd80cc02edde/runtime_results.json
  limits: `mach-register` is witnessed via `sandbox_check` (callout), not a `bootstrap_register*` syscall path

### Probe/program

- Native probes (built via `book/api/runtime/native/probes/build.sh`):
  - `book/api/runtime/native/probes/sandbox_mach_probe.c` (`bootstrap_look_up`, resolve)
  - `book/api/runtime/native/probes/sandbox_check_self_apply_probe.c` (`sandbox_check`, publish decision)
- Profile under test: `book/evidence/experiments/runtime-final-final/suites/mach-name-equivalence/sb/mach_name_equivalence.sb`
- Apply-gate preflight: `PYTHONPATH=. python3 book/tools/preflight/preflight.py scan book/evidence/experiments/runtime-final-final/suites/mach-name-equivalence/sb/mach_name_equivalence.sb` → `classification=no_known_apply_gate_signature`
- Names:
  - AA = `com.apple.cfprefsd.agent`
  - BB = `com.apple.cfprefsd.agent.sandboxlore` (deterministic suffix variant)

### Output matrix (observed `actual`)

| operation | AA | BB |
| --- | --- | --- |
| `mach-lookup` | allow | deny |
| `mach-register` | allow | deny |

Matrix extraction (from the cited `runtime_results.json`):

```sh
jq '.["mach-name-equivalence"].probes[] | {operation, name: .path, actual}' \
  book/evidence/experiments/runtime-final-final/suites/mach-name-equivalence/out/775d1303-74cf-403c-85a4-fd80cc02edde/runtime_results.json
```

### Interpretation

On this host baseline, granting `global-name` permission for AA does **not** carry over to BB for either `mach-lookup` (resolve) or `mach-register` (publish). For this AA→BB derivation, the induced AA/BB allow/deny relationship is the same for publish and resolve.

### Falsification

claim:
  world_id: sonoma-14.4.1-23E224-arm64-dyld-2c0602c5
  status: ok
  stage: operation
  lane: scenario
  command: `book/api/runtime/native/probes/sandbox_check_self_apply_matrix_probe` (launched via launchd from a staged `/private/tmp` root; see the cited `job.plist`)
  evidence:
    - book/evidence/experiments/runtime-final-final/suites/mach-name-equivalence/sb/mach_name_falsification_publish_only.sb
    - book/api/runtime/native/probes/sandbox_check_self_apply_matrix_probe.c
    - book/evidence/experiments/runtime-final-final/suites/mach-name-equivalence/falsification/0b87ab83-6cff-4270-95c6-9f895f099096/stdout.txt
    - book/evidence/experiments/runtime-final-final/suites/mach-name-equivalence/falsification/0b87ab83-6cff-4270-95c6-9f895f099096/job.plist
  limits: this is a `sandbox_check` decision witness (not a `bootstrap_*` syscall path); and the asymmetric profile makes `mach-lookup` deny regardless of name, so it cannot discriminate name-matching semantics for resolve

- Profile (intentionally asymmetric):
  - `(allow mach-register (global-name "com.sandboxlore.falsify.globalname"))`
  - `(deny mach-lookup)` (global deny; `deny default` also applies)
- Preflight: `PYTHONPATH=. python3 book/tools/preflight/preflight.py scan book/evidence/experiments/runtime-final-final/suites/mach-name-equivalence/sb/mach_name_falsification_publish_only.sb` → `classification=no_known_apply_gate_signature`
- Names:
  - AA = `com.sandboxlore.falsify.globalname`
  - BB = `AA + "." + getpid()` (example run: `.../stdout.txt` shows `BB=com.sandboxlore.falsify.globalname.6838`)

Observed raw `sandbox_check` `(rc, errno)` matrix:

| operation | AA | BB |
| --- | --- | --- |
| `mach-register` | (0, 0) | (1, 0) |
| `mach-lookup` | (1, 0) | (1, 0) |

Interpretation: under this intentionally asymmetric profile, `mach-register` distinguishes AA vs BB while `mach-lookup` denies both, so the AA/BB equivalence relation differs across publish vs resolve for this profile. This does not contradict the earlier equivalence witness, because the earlier witness is about the AA→BB name-variant relationship when the operation is permitted for AA (here, `mach-lookup` is denied globally).

### Status

- ok

### Thread context

This proof was produced from a process context where the interactive harness was already sandbox-constrained, so I treated any direct-run observations as potentially confounded and avoided using them as decision-stage evidence.

The clean evidence path here is `book.api.runtime` with the `launchd_clean` channel, which stages the repo and starts a fresh worker via launchd so the worker begins unsandboxed and can enter the SBPL profile at operation stage.

The relevant substrate question is an equivalence question over `global-name` strings: given a profile that grants AA under the `global-name` filter, does the induced allow/deny relationship between AA and a deterministically derived BB match across the publish operation (`mach-register`) and the resolve operation (`mach-lookup`)?

The existing `mach-name-equivalence` suite already had a concrete AA/BB pairing and a deny-default profile, but it previously lacked a publish-side operation witness; in this thread, the focus was to make `mach-register` observable at operation stage without weakening the baseline or shifting to non-canonical tooling.

An initial attempt to use a Python/ctypes implementation of `sandbox_check` for typed filters failed on this host with `EFAULT` behavior, which I treated as a harness/tooling failure rather than as a policy decision; the likely cause was varargs ABI mismatch in the ctypes call path (uncertain).

To remove that confounder, the thread introduced a native probe path for `sandbox_check`, so the publish-side decision could be captured as a small standalone program rather than as a fragile FFI call.

Running that check under an exec-wrapper apply model (`sandbox_runner`) exposed another confounder: when the sandbox is entered before `exec`, the probe binary itself can fall under bootstrap-stage restrictions (for example, file-read constraints on the staged path), which can prevent reaching the intended operation at all.

The self-apply model in `book/api/runtime/native/probes/sandbox_check_self_apply_probe.c` addresses that by reading the SBPL profile text (unsandboxed), calling `sandbox_init`, and only then issuing the single `sandbox_check` query, so the only policy-facing action is the intended operation.

The `mach-lookup` half remained on `book/api/runtime/native/probes/sandbox_mach_probe.c` because plan validation expects an in-process driver for deny-default `mach-lookup` probes, and because it yields a syscall-adjacent witness (`bootstrap_look_up`) rather than only a callout.

With those roles separated, a `launchd_clean` scenario-lane run produced a committed bundle and the extracted matrix showing that AA is allowed and BB is denied for both `mach-lookup` and `mach-register`, which is the minimal black-box witness for “same equivalence relationship” for this AA→BB derivation on this world.
