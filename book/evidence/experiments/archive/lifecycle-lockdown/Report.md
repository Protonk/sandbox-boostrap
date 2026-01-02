# lifecycle-lockdown (Report)

Baseline: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5` (Sonoma 14.4.1 / 23E224, arm64).

## Purpose

Evaluate whether `book.api.lifecycle` probe outputs are supportable by independent witnesses on this host baseline.

This report summarizes the first host runs of `run_lockdown.py` and records what is (and is not) supportable from the committed artifacts.

## How to run
Run the runtime slice via the runtime CLI (bundles are committed under the chosen out root; `LATEST` points to the most recent run):

```sh
python -m book.api.runtime run \
  --plan book/evidence/experiments/lifecycle-lockdown/plan.json \
  --channel launchd_clean \
  --out book/evidence/experiments/lifecycle-lockdown/out/runtime/launchd_clean_enforce
```

## Open questions

See `book/evidence/experiments/lifecycle-lockdown/Plan.md`.

## Evidence (expected locations)

- Entitlements cross-check outputs under `book/evidence/experiments/lifecycle-lockdown/out/entitlements/`
- Apply cross-check outputs under `book/evidence/experiments/lifecycle-lockdown/out/apply/`
- Execution-lane isolation runtime bundles under `book/evidence/experiments/lifecycle-lockdown/out/runtime/`
- Baseline reachability lane outputs under each runtime bundle (`baseline_results.json`).

Note: legacy runtime bundles were pruned during runtime cleanup. Rerun the plan to regenerate bundles under `out/runtime/`; run-id paths below are historical until rerun.

## Results (current)

### A) Entitlements + signing metadata

Observation: `book.api.lifecycle entitlements` agrees with `codesign` about “entitlements present” for the same binary across two signing variants.

- Unsigned build:
  - Security.framework view: `entitlements_present=false`, `signing_identifier=entitlements_example`
  - codesign view: no entitlements payload reported
- Ad-hoc signed with explicit (empty) entitlements plist:
  - Security.framework view: `entitlements_present=true`, `signing_identifier` changes (adhoc id suffix)
  - codesign view: entitlements payload reported as an empty dict (`<dict></dict>`)

Evidence:
- `book/evidence/experiments/lifecycle-lockdown/out/entitlements/summary.json`
- `book/evidence/experiments/lifecycle-lockdown/out/entitlements/entitlements_unsigned.json`
- `book/evidence/experiments/lifecycle-lockdown/out/entitlements/entitlements_signed.json`
- `book/evidence/experiments/lifecycle-lockdown/out/entitlements/codesign_entitlements_signed.stdout.txt`

Tier: `mapped` (metadata visibility on this host).

### B) Apply attempts + preflight + wrapper markers

Observation: wrapper-side preflight classification and wrapper markers line up, but this harness environment appears to block apply even for a “passing neighbor” profile.

- Gate SBPL shape (`minimal_failing.sb`):
  - Preflight scan: `likely_apply_gated_for_harness_identity`
  - Wrapper + API with preflight `enforce`: preflight blocks before apply (no `sbpl-apply` markers).
  - Wrapper + API with preflight `force`: apply is attempted and fails with `errno=1 (EPERM)` for both:
    - SBPL mode (`sandbox_init`)
    - blob mode (`sandbox_apply`)
- Passing neighbor (`passing_neighbor.sb`):
  - Wrapper preflight marker: `no_known_apply_gate_signature`
  - Apply still fails with `errno=1 (EPERM)` (`sandbox_init` in SBPL mode, `sandbox_apply` in blob mode).

This means the experiment has not yet separated “profile-shape apply gating” from “ambient harness constraint that blocks sandbox_init/sandbox_apply”.

Evidence:
- `book/evidence/experiments/lifecycle-lockdown/out/apply/summary.json`
- `book/evidence/experiments/lifecycle-lockdown/out/apply/api_apply_attempt_passing.json`
- `book/evidence/experiments/lifecycle-lockdown/out/apply/api_apply_attempt_gate.json`
- `book/evidence/experiments/lifecycle-lockdown/out/apply/wrapper_sbpl_passing.stderr.txt`
- `book/evidence/experiments/lifecycle-lockdown/out/apply/wrapper_sbpl_gate_force.stderr.txt`
- `book/evidence/experiments/lifecycle-lockdown/out/apply/wrapper_blob_gate_force.stderr.txt`

Tier: `hypothesis` (apply-stage EPERM; confounded by harness/environment constraints).

#### B2) Execution-lane isolation via `book.api.runtime` (`launchd_clean`)

Observation: when rerun under `launchd_clean`, the “passing neighbor” no longer fails at apply stage, while the known gated profile continues to fail with apply-stage `EPERM` when preflight is forced.

This separates the earlier “everything EPERM” outcome (direct harness lane) from profile-shape apply gating (known-gated profile).

Runtime note: baseline lane is now enabled as a reachability sanity lane (`baseline_results.json`); oracle lane remains disabled in `book/evidence/experiments/lifecycle-lockdown/plan.json`.

- Preflight enforce run (`launchd_clean`, `SANDBOX_LORE_PREFLIGHT_FORCE=0`):
  - Passing profiles: `failure_stage=probe` (no apply-stage error observed)
  - Gate profiles: `failure_stage=preflight` (`preflight_apply_gate_signature`)
- Preflight force run (`launchd_clean`, `SANDBOX_LORE_PREFLIGHT_FORCE=1`):
  - Passing profiles: `failure_stage=probe` (no apply-stage error observed)
  - Gate profiles: `failure_stage=apply` with `errno=1 (EPERM)` for both:
    - `sandbox_init_failed` (SBPL mode)
    - `sandbox_apply_failed` (blob mode)

Notes:
- The probe used here is intentionally “small”, but it is currently not producing operation-stage evidence (`exit_code=127`, `failure_stage=probe`) for the “passing neighbor”. This does **not** look like apply-stage gating (the gate profile still fails at apply, and the passing profile no longer does). It does mean we have not yet established any policy semantics from these runtime bundles.

Evidence:
- `book/evidence/experiments/lifecycle-lockdown/out/runtime/launchd_clean_enforce/8d20c8f6-6ed3-4ca6-b0bd-da17599b18a9/runtime_results.json`
- `book/evidence/experiments/lifecycle-lockdown/out/runtime/launchd_clean_force/4406014b-65cc-4753-a550-1200d966734d/runtime_results.json`

Tier: `hypothesis` (still apply-stage evidence; bounded by lane separation).

#### B3) Bootstrap exec: marker suppression + `execvp` `EPERM`

Observation: in a follow-up `launchd_clean` run (`plan_id lifecycle-lockdown.v2.exec-stage-diagnosis`), adding `(allow file-write-data)` is sufficient to restore post-apply wrapper markers, which then show that the probe never reaches operation stage because `execvp()` fails with `errno=1 (EPERM)` at `stage=exec`.

This is evidence about the **bootstrap/exec** stage, not sandbox operation semantics.

Key comparisons (all `lane=scenario`):

- `lockdown:airlock_passing_sbpl` (no extra rules):
  - `exit_code=127`, `stderr=""` (no post-apply markers visible)
  - runtime tool classifies `failure_stage=probe` (`probe_nonzero_exit`), but there is no proof the probe ever ran.
- `lockdown:airlock_passing_sbpl_write` (`+ (allow file-write-data)`):
  - wrapper markers are visible and show `sandbox_init` succeeded (`stage=applied`)
  - `execvp()` fails with `errno=1 (EPERM)` at `stage=exec` for `argv0=.../file_probe`
- `lockdown:airlock_passing_sbpl_write_mapexec` (`+ file-write-data + file-map-executable` for `/System/Library` and `/usr/lib`):
  - same `execvp()` `EPERM` result as `..._write` (no improvement)
- `lockdown:airlock_passing_sbpl_write_read_launchctl` (`+ file-write-data + file-read*` for `/private/tmp/sandbox-lore-launchctl`):
  - same `execvp()` `EPERM` result as `..._write` (no improvement)

Representative marker excerpt (from `lockdown:airlock_passing_sbpl_write`, stderr captured in `runtime_results.json`):

```jsonl
{"tool":"sbpl-apply","marker_schema_version":1,"stage":"apply","mode":"sbpl","api":"sandbox_init","rc":0,"errno":0,"err_class":"ok","err_class_source":"none",...}
{"tool":"sbpl-apply","marker_schema_version":1,"stage":"applied","mode":"sbpl","api":"sandbox_init","rc":0,...}
{"tool":"sbpl-apply","marker_schema_version":1,"stage":"exec","rc":-1,"errno":1,"argv0":".../book/api/runtime/native/file_probe/file_probe",...}
execvp: Operation not permitted
```

Interpretation (cause, not yet proved): this `execvp()` `EPERM` is **not** explained by “missing `file-read*` for `/private/tmp/sandbox-lore-launchctl`” alone (that addition does not change the result) and is also not fixed by narrowly allowing `file-map-executable` for common system library locations.

Evidence:
- Runtime bundle (preflight enforce): `book/evidence/experiments/lifecycle-lockdown/out/runtime/launchd_clean_enforce/7ff2530c-ce4f-44d9-a43f-da3383a7984b/runtime_results.json`
- Generated SBPL (showing `process-exec*` + no `file-read*` for `/private/tmp`): `book/evidence/experiments/lifecycle-lockdown/out/runtime/launchd_clean_enforce/7ff2530c-ce4f-44d9-a43f-da3383a7984b/runtime_profiles/passing_neighbor.lockdown_airlock_passing_sbpl.runtime.sb`
- Same, with `(allow file-write-data)`: `book/evidence/experiments/lifecycle-lockdown/out/runtime/launchd_clean_enforce/7ff2530c-ce4f-44d9-a43f-da3383a7984b/runtime_profiles/passing_neighbor.lockdown_airlock_passing_sbpl_write.runtime.sb`
- Same, with added `file-map-executable` (no change observed): `book/evidence/experiments/lifecycle-lockdown/out/runtime/launchd_clean_enforce/7ff2530c-ce4f-44d9-a43f-da3383a7984b/runtime_profiles/passing_neighbor.lockdown_airlock_passing_sbpl_write_mapexec.runtime.sb`
- Same, with added `file-read*` for `/private/tmp/sandbox-lore-launchctl` (no change observed): `book/evidence/experiments/lifecycle-lockdown/out/runtime/launchd_clean_enforce/f2118065-6f7c-4445-9006-63b01240034b/runtime_profiles/passing_neighbor.lockdown_airlock_passing_sbpl_write_read_launchctl.runtime.sb`
- Runtime bundle showing `execvp()` `EPERM` persists under `..._write_read_launchctl`: `book/evidence/experiments/lifecycle-lockdown/out/runtime/launchd_clean_enforce/f2118065-6f7c-4445-9006-63b01240034b/runtime_results.json`

Tier: `mapped` (bootstrap-stage, scenario-scoped, from a runtime bundle; not operation semantics).

#### B4) System-binary pivot: `execvp()` `EPERM` also blocks `/usr/sbin/sysctl`

Observation: switching the probe to a system binary (`sysctl -n kern.osrelease`) does not avoid the bootstrap failure. `execvp()` still fails with `errno=1 (EPERM)` at `stage=exec` for `argv0=/usr/sbin/sysctl`, even when adding a broader `file-map-executable` allowlist for standard system paths.

This makes the failure look less like “repo-staging-root only” and more like “general exec prerequisite missing” under the current runtime shim ruleset.

Representative marker excerpt (from `lockdown:airlock_passing_sbpl_write_mapexec_sysctl`, stderr captured in `runtime_results.json`):

```jsonl
{"tool":"sbpl-apply","marker_schema_version":1,"stage":"apply","mode":"sbpl","api":"sandbox_init","rc":0,"errno":0,"err_class":"ok","err_class_source":"none",...}
{"tool":"sbpl-apply","marker_schema_version":1,"stage":"applied","mode":"sbpl","api":"sandbox_init","rc":0,...}
{"tool":"sbpl-apply","marker_schema_version":1,"stage":"exec","rc":-1,"errno":1,"argv0":"/usr/sbin/sysctl",...}
execvp: Operation not permitted
```

Evidence:
- Runtime bundle (preflight enforce): `book/evidence/experiments/lifecycle-lockdown/out/runtime/launchd_clean_enforce/d4e96281-6046-4405-81de-535fd29e8890/runtime_results.json`
- Generated SBPL for sysctl probe (shows `process-exec*` + `file-read*` on `/usr` + `file-write-data`): `book/evidence/experiments/lifecycle-lockdown/out/runtime/launchd_clean_enforce/d4e96281-6046-4405-81de-535fd29e8890/runtime_profiles/passing_neighbor.lockdown_airlock_passing_sbpl_write_sysctl.runtime.sb`
- Same, with expanded `file-map-executable` allowlist (no change observed): `book/evidence/experiments/lifecycle-lockdown/out/runtime/launchd_clean_enforce/d4e96281-6046-4405-81de-535fd29e8890/runtime_profiles/passing_neighbor.lockdown_airlock_passing_sbpl_write_mapexec_sysctl.runtime.sb`

Tier: `mapped` (bootstrap-stage, scenario-scoped, from a runtime bundle; not operation semantics).

#### B5) `allow default` is a decisive bootstrap knob for SBPL `(version 2)`

Observation: for these SBPL `(version 2)` runtime profiles, adding `(allow default)` is the first (and so far only) experiment-local knob that changes `execvp()` from `EPERM` to success for both:

- a system binary (`/usr/sbin/sysctl`), and
- a repo-staged probe binary (`.../book/api/runtime/native/file_probe/file_probe` in the `launchd_clean` staging root).

This is bootstrap evidence (it unblocks “run anything after apply”), not policy semantics.

Evidence (sysctl succeeds under `(allow default)`):
- Runtime bundle: `book/evidence/experiments/lifecycle-lockdown/out/runtime/launchd_clean_enforce/6629c56b-2729-4cc0-be08-5d3a6b7be0a2/runtime_results.json`
- Generated SBPL (`(allow default)` appended): `book/evidence/experiments/lifecycle-lockdown/out/runtime/launchd_clean_enforce/6629c56b-2729-4cc0-be08-5d3a6b7be0a2/runtime_profiles/passing_neighbor.lockdown_airlock_passing_sbpl_write_allow_default_sysctl.runtime.sb`

Evidence (file_probe runs and yields operation-stage evidence under `(allow default)`):
- Runtime bundle: `book/evidence/experiments/lifecycle-lockdown/out/runtime/launchd_clean_enforce/be733a4a-1903-4028-bad7-80f07ecd18ef/runtime_results.json`
- Generated SBPL (`(allow default)` appended): `book/evidence/experiments/lifecycle-lockdown/out/runtime/launchd_clean_enforce/be733a4a-1903-4028-bad7-80f07ecd18ef/runtime_profiles/passing_neighbor.lockdown_airlock_passing_sbpl_write_allow_default_fileprobe.runtime.sb`

Negative controls (selected): `file-map-executable` (even unfiltered), `mach-lookup` (unfiltered), `file-read*` (unfiltered), and several path-scoped expansions did not clear the `execvp()` `EPERM`; see bundles under `book/evidence/experiments/lifecycle-lockdown/out/runtime/launchd_clean_enforce/` with plan_ids `lifecycle-lockdown.v4.exec-stage-system-binary-pivot` through `lifecycle-lockdown.v14.exec-stage-codesigning`.

Tier: `mapped` (bootstrap-stage, scenario-scoped, from committed runtime bundles; not operation semantics).

#### B6) `debug` is not available in SBPL `(version 2)` (apply-time failure)

Observation: attempting to add `(debug deny)` (to get unified-log deny records) fails at `sandbox_init` time with an “unbound variable: debug” error.

Evidence:
- Runtime bundle (apply fails): `book/evidence/experiments/lifecycle-lockdown/out/runtime/launchd_clean_enforce/b8557b5d-fa11-40c5-bcb6-72cda15a61f7/runtime_results.json`

Tier: `mapped` (apply-stage structural/compiler error; not semantics).

#### B7) Exec-prereq narrowing: still no substitute for `(allow default)`

Observation: several additional “likely exec prerequisites” do **not** unblock the bootstrap `execvp()` `EPERM` under SBPL `(version 2)` when `(allow default)` is absent:

- `process-exec*` with an explicit path predicate (`(subpath "/")`)
- `process-exec` (no `*`) with an explicit path predicate (`(subpath "/")`)
- `mach-bootstrap` (and `mach-bootstrap` + `mach-register`)
- `file-ioctl`
- `file-search`
- `file-test-existence` (and `file-search` + `file-test-existence`)

All of these variants still fail at `failure_stage=bootstrap` with `errno=1 (EPERM)` and `exit_code=127`.

Evidence:
- Narrow variant bundle (process-exec*, mach-bootstrap/register, file-ioctl): `book/evidence/experiments/lifecycle-lockdown/out/runtime/launchd_clean_enforce/ebd53423-8af4-4841-9dd9-1133fea07a9b/runtime_results.json`
- `file-search` / `file-test-existence` variants: `book/evidence/experiments/lifecycle-lockdown/out/runtime/launchd_clean_enforce/2c77975f-808c-47b5-a92a-9beda16f2f1d/runtime_results.json`
- `process-exec` (no `*`) variant: `book/evidence/experiments/lifecycle-lockdown/out/runtime/launchd_clean_enforce/a36ce479-765f-4e3d-9102-863225f7d6d3/runtime_results.json`

Tier: `mapped` (bootstrap-stage, scenario-scoped, from committed runtime bundles; not operation semantics).

#### B8) Allow-default deny scan: some “obvious” prerequisites are not required (for sysctl)

Observation: adding targeted denies on top of a working `(allow default)` profile does **not** reintroduce the bootstrap `execvp()` `EPERM` for `/usr/sbin/sysctl` in this harness, except for denying `process-exec*` itself.

- Sanity check: `(deny process-exec*)` does reintroduce bootstrap failure (`exit_code=127`, `failure_stage=bootstrap`).
- The following targeted denies do **not** break sysctl execution (still `exit_code=0`, stdout `23.4.0`):
  - `mach-lookup`
  - `mach-bootstrap`
  - `file-map-executable`
  - `process-codesigning`
  - `process-legacy-codesigning*`
  - `process-legacy-codesigning-status*`
  - `file-ioctl`

This does **not** prove those operations never participate in exec/dyld; it only bounds the “single missing prerequisite” hypothesis for this sysctl bootstrap path.

Evidence:
- Allow-default deny scan v1: `book/evidence/experiments/lifecycle-lockdown/out/runtime/launchd_clean_enforce/52401592-67fb-473e-af25-f9217d21a925/runtime_results.json`
- Allow-default deny scan v2 (legacy codesigning): `book/evidence/experiments/lifecycle-lockdown/out/runtime/launchd_clean_enforce/81b5ae10-79c6-4db5-a3a8-524d6fca9d3f/runtime_results.json`

Tier: `mapped` (bootstrap-stage, scenario-scoped, from committed runtime bundles; not operation semantics).

## Next step (needs direction)

The “missing exec prerequisite” remains unknown beyond “`(allow default)` makes bootstrap exec succeed.”

To narrow further, the experiment likely needs a new witness channel that can attribute `execvp()` `EPERM` to a specific operation/filter (for example: a local wrapper/probe that calls `sandbox_check` / `sandbox_check_by_audit_token` after `sandbox_init`, or a local-in-experiment build of `sandbox_runner` that emits those callouts), since SBPL `(version 2)` does not accept `(debug deny)` and unified-log deny records were not obtained via SBPL directives.

## Limits

- This experiment is host-scoped and does not generalize beyond `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
- Apply-stage `EPERM` remains apply-stage evidence; it is not a policy decision.
