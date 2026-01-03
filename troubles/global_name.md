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

### Status

- ok
