# Examples

This file is a menagerie of working, host-bound examples that exercise both trace and shrink. Each example points to an `out/` run directory so the artifacts are concrete and inspectable on this host (`world_id sonoma-14.4.1-23E224-arm64-dyld-a3a840f9`). Treat interpretations here as partial until promoted.

## How to read the examples

Each example includes:
- A run directory with concrete artifacts (`profiles/trace.sb`, `profiles/shrunk.sb`, logs, metrics).
- A trace view (how the allow rules are built from denials).
- A shrink view (what rules are required after minimization and why).

## Example A: Baseline file + sysctl + lookup (sandbox_target)

Run directory:
- `book/evidence/experiments/runtime-final-final/suites/shrink-trace/out/trace_baseline`

Trace view:
- The profile grows from `(deny default)` to allow `file-read-data` on `/private/etc/hosts`, `sysctl-read` for `kern.ostype`, and `mach-lookup` for libinfo services.
- This is the canonical “build up from denials” shape for a small deterministic workload.

Shrink view:
- The minimized profile keeps both `file-write-create` and `file-write-data` for `out/hello.txt`. This is the create vs truncate split: the first run creates the file, later runs need write-data for `O_TRUNC`.
- The two-state shrink check (fresh + repeat) is what makes this stable.

Profile meaning (real-life):
- The profile is a tight allowlist for a program that reads `/etc/hosts`, queries a kernel sysctl, resolves a user via libinfo, and writes a single output file under its work dir.

Why it is tricky:
- A profile that only allows create can pass the first run and fail the repeat run; shrink must preserve both operations.

How to re-run:
```
OUT_DIR=./out/trace_baseline FIXTURE_BIN=sandbox_target ./scripts/run_workflow.sh
```

Key artifacts:
- `book/evidence/experiments/runtime-final-final/suites/shrink-trace/out/trace_baseline/profiles/trace.sb`
- `book/evidence/experiments/runtime-final-final/suites/shrink-trace/out/trace_baseline/profiles/shrunk.sb`
- `book/evidence/experiments/runtime-final-final/suites/shrink-trace/out/trace_baseline/phases/trace/metrics.jsonl`

## Example B: Required network (sandbox_net_required)

Run directory:
- `book/evidence/experiments/runtime-final-final/suites/shrink-trace/out/shrink_net_required`

Trace view:
- The trace phase must emit a `network-outbound` rule or the fixture fails (EPERM is fatal; ECONNREFUSED is OK).
- This example forces network parsing to be correct and present in the traced profile.

Shrink view:
- The minimized profile must retain `network-outbound (remote ip "*:2000")` or the required connect fails.
- This shows shrink can collapse unrelated rules while preserving required network access.

Profile meaning (real-life):
- The profile is a tight allowlist for a program that needs a local outbound connect as a required operation.

Why it is tricky:
- Network filters are syntactically strict; normalization to `*` or `localhost` is required to avoid parse failures.

How to re-run:
```
OUT_DIR=./out/shrink_net_required FIXTURE_BIN=sandbox_net_required ./scripts/run_workflow.sh
```

Key artifacts:
- `book/evidence/experiments/runtime-final-final/suites/shrink-trace/out/shrink_net_required/profiles/trace.sb`
- `book/evidence/experiments/runtime-final-final/suites/shrink-trace/out/shrink_net_required/profiles/shrunk.sb`
- `book/evidence/experiments/runtime-final-final/suites/shrink-trace/out/shrink_net_required/phases/shrink/stdout.txt`

## Example C: Subprocess execution (sandbox_spawn)

Run directory:
- `book/evidence/experiments/runtime-final-final/suites/shrink-trace/out/shrink_spawn`

Trace view:
- The profile must add `process-fork` and `process-exec*` for `/usr/bin/id` because the fixture spawns a child.
- Deny extraction uses `DENY_SCOPE=all` to capture child-process denies.

Shrink view:
- The minimized profile keeps only the child-execution rules and removes unrelated allowances.

Profile meaning (real-life):
- This is a tiny policy for a parent that only needs to spawn a single system binary.

Why it is tricky:
- PID-scoped tracing can miss child denies; the PID-agnostic extraction is required for this example to converge.

How to re-run:
```
OUT_DIR=./out/shrink_spawn FIXTURE_BIN=sandbox_spawn ./scripts/run_workflow.sh
```

Key artifacts:
- `book/evidence/experiments/runtime-final-final/suites/shrink-trace/out/shrink_spawn/profiles/shrunk.sb`
- `book/evidence/experiments/runtime-final-final/suites/shrink-trace/out/shrink_spawn/phases/trace/metrics.jsonl`

## Example D: Loader boundary (sandbox_min, seed off)

Run directory:
- `book/evidence/experiments/runtime-final-final/suites/shrink-trace/out/trace_min`

Trace view:
- With `SEED_DYLD=0`, the first iterations can `SIGABRT` before denies are fully captured, but the trace still converges after rule growth.
- This run surfaces early loader dependencies without fixture noise.

Shrink view:
- The minimized profile is small but still includes `file-read-data` for `/`, indicating a minimal loader dependency on this host.

Profile meaning (real-life):
- A deny-by-default profile for a trivial program still needs a small set of loader allowances before user code runs.

Why it is tricky:
- Early aborts can look like “no denies”; this example uses log capture plus repeatable-success to keep progressing.

How to re-run:
```
OUT_DIR=./out/trace_min SEED_DYLD=0 FIXTURE_BIN=sandbox_min ./scripts/run_workflow.sh
```

Key artifacts:
- `book/evidence/experiments/runtime-final-final/suites/shrink-trace/out/trace_min/phases/trace/status.json`
- `book/evidence/experiments/runtime-final-final/suites/shrink-trace/out/trace_min/profiles/shrunk.sb`

## Example E: Dyld import sensitivity (matrix contrast)

Run directories:
- `book/evidence/experiments/runtime-final-final/suites/shrink-trace/out/matrix/sandbox_target_dyld1_netparsed_streak2`
- `book/evidence/experiments/runtime-final-final/suites/shrink-trace/out/matrix/sandbox_target_dyld0_netparsed_streak2`

Trace view:
- With `import_dyld_support=1`, the traced profile is smaller and converges in fewer iterations.
- With `import_dyld_support=0`, the traced profile is larger on this host, indicating more loader-related denials were observed before convergence.

Shrink view:
- Both runs shrink to a small, stable profile, but the dyld-imported run shrinks from a smaller trace surface.

Profile meaning (real-life):
- This contrast isolates how much of the initial deny surface is loader-bound vs fixture-bound on this host.

Why it is tricky:
- Without a contrast run, it is easy to misattribute early denials to the fixture rather than the loader.

How to re-run:
```
OUT_DIR=./out/matrix/sandbox_target_dyld1_netparsed_streak2 FIXTURE_BIN=sandbox_target IMPORT_DYLD_SUPPORT=1 NETWORK_RULES=parsed SUCCESS_STREAK=2 ./scripts/run_workflow.sh
OUT_DIR=./out/matrix/sandbox_target_dyld0_netparsed_streak2 FIXTURE_BIN=sandbox_target IMPORT_DYLD_SUPPORT=0 NETWORK_RULES=parsed SUCCESS_STREAK=2 ./scripts/run_workflow.sh
```

Key artifacts:
- `book/evidence/experiments/runtime-final-final/suites/shrink-trace/out/matrix/summary.json` (matrix summary)
- `book/evidence/experiments/runtime-final-final/suites/shrink-trace/out/matrix/sandbox_target_dyld1_netparsed_streak2/profiles/trace.sb`
- `book/evidence/experiments/runtime-final-final/suites/shrink-trace/out/matrix/sandbox_target_dyld0_netparsed_streak2/profiles/trace.sb`

## Example F: Unused rule removal (manual shrink)

Run directory:
- `book/evidence/experiments/runtime-final-final/suites/shrink-trace/out/shrink_unused`

Trace view:
- The trace phase produces a normal baseline profile for `sandbox_target`.

Shrink view:
- An extra, unused rule was appended and then removed by a manual shrink run.
- This shows the shrinker can collapse a permissive profile by deleting rules that do not affect the program’s success contract.

Profile meaning (real-life):
- This demonstrates how shrink can strip accidental allowances without breaking required behavior.

Why it is tricky:
- The shrinker must validate both fresh and repeat runs to avoid removing first-run-only permissions.

How to re-run:
```
OUT_DIR=./out/shrink_unused FIXTURE_BIN=sandbox_target ./scripts/run_workflow.sh
(cd ./out/shrink_unused && echo '(allow network-outbound (remote ip "*:443"))' >> profiles/trace.sb)
(cd ./out/shrink_unused && SHRINK_DIR=./phases/shrink SHRUNK_PROFILE=./profiles/shrunk_manual.sb ../../scripts/shrink_instrumented.sh ./artifacts/bin/sandbox_target ./profiles/trace.sb | tee phases/shrink/stdout_manual.txt)
```

Key artifacts:
- `book/evidence/experiments/runtime-final-final/suites/shrink-trace/out/shrink_unused/profiles/trace.sb`
- `book/evidence/experiments/runtime-final-final/suites/shrink-trace/out/shrink_unused/phases/shrink/stdout_manual.txt`

## Example G: Network rule mode failure (required connect)

Run directories:
- `book/evidence/experiments/runtime-final-final/suites/shrink-trace/out/matrix/sandbox_net_required_dyld1_netparsed_streak2`
- `book/evidence/experiments/runtime-final-final/suites/shrink-trace/out/matrix/sandbox_net_required_dyld1_netdrop_streak2`

Trace view:
- With `NETWORK_RULES=parsed`, the trace loop emits a `network-outbound` rule and converges.
- With `NETWORK_RULES=drop`, the trace loop cannot add the required rule, and the run ends `no_new_rules` even though the required connect still fails.

Shrink view:
- The parsed run retains `network-outbound (remote ip "*:2000")` through shrink because the connect is required.
- The drop run never reaches a shrink phase because the trace cannot converge.

Profile meaning (real-life):
- This example shows that “dropping network rules” is not a benign simplification: it breaks workloads that require network access to be permitted.

Why it is important:
- The fixture treats `EPERM` as failure and `ECONNREFUSED` as success. That makes network permission a hard requirement rather than optional noise.
- The `NETWORK_RULES=drop` run is a falsification case: it demonstrates that the trace loop can appear to “stall cleanly” while still failing to satisfy a required capability.
- This contrast keeps the network parsing path honest and ensures the tool is not silently succeeding by ignoring a required behavior.

How to re-run:
```
OUT_DIR=./out/matrix/sandbox_net_required_dyld1_netparsed_streak2 FIXTURE_BIN=sandbox_net_required IMPORT_DYLD_SUPPORT=1 NETWORK_RULES=parsed SUCCESS_STREAK=2 ./scripts/run_workflow.sh
OUT_DIR=./out/matrix/sandbox_net_required_dyld1_netdrop_streak2 FIXTURE_BIN=sandbox_net_required IMPORT_DYLD_SUPPORT=1 NETWORK_RULES=drop SUCCESS_STREAK=2 ./scripts/run_workflow.sh
```

Key artifacts:
- `book/evidence/experiments/runtime-final-final/suites/shrink-trace/out/matrix/summary.json` (matrix summary)
- `book/evidence/experiments/runtime-final-final/suites/shrink-trace/out/matrix/sandbox_net_required_dyld1_netparsed_streak2/profiles/shrunk.sb`
- `book/evidence/experiments/runtime-final-final/suites/shrink-trace/out/matrix/sandbox_net_required_dyld1_netdrop_streak2/phases/trace/status.json`

## Convergence and Stability

Convergence is not just "the trace loop stopped." In this experiment, convergence means two things: (1) the trace loop reaches a repeatable-success stop (success streak with no new rules) and (2) the shrunk profile succeeds on both a fresh run and a repeat run. This matters because the workflow is built on deprecated system hooks (`sandbox-exec` + unified logs). When convergence is unstable, it can indicate tool limitations (log capture, parser choices, stop conditions) or real sandbox characteristics (loader dependencies, required operations). The sections below show how we distinguish these, using concrete host-bound evidence.

### Signals of tool limitation (partial)

- **Network rules dropped for a required workload**: the required-connect fixture fails to converge when `NETWORK_RULES=drop` even though the operation is required. In the matrix this shows up as `trace_status=no_new_rules` for `sandbox_net_required_dyld1_netdrop_streak2` and `sandbox_net_required_dyld1_netdrop_streak3` in `book/evidence/experiments/runtime-final-final/suites/shrink-trace/out/matrix/summary.json`. This is a tool choice, not a sandbox constraint, and it produces a false "clean stop."
- **Stop-condition sensitivity**: the same fixture and host can converge under one streak but stop early under another (for example, `sandbox_target_dyld1_netparsed_streak2` succeeded while `sandbox_target_dyld1_netparsed_streak3` ended `no_new_rules` in `book/evidence/experiments/runtime-final-final/suites/shrink-trace/out/matrix/summary.json`). This suggests sensitivity to log timing or deny capture, not a stable sandbox requirement.
- **High rejected-rule counts**: runs with large `bad_rules` counts (for example, `sandbox_net_required_dyld1_netparsed_streak3` reports `bad_rules=419` in `book/evidence/experiments/runtime-final-final/suites/shrink-trace/out/matrix/summary.json`) indicate parser noise or deny formats that the rule generator cannot safely encode. This is a tooling limitation, not an inherent sandbox requirement.

### Signals of sandbox characteristics (partial)

- **Dyld import reduces the deny surface**: with `IMPORT_DYLD_SUPPORT=1`, trace profiles are smaller than their `IMPORT_DYLD_SUPPORT=0` counterparts (for example, `trace_lines=37` vs `49` for `sandbox_target` in `book/evidence/experiments/runtime-final-final/suites/shrink-trace/out/matrix/summary.json`). This indicates real loader dependencies on this host rather than fixture behavior.
- **Loader boundary aborts that still converge**: `sandbox_min` with `SEED_DYLD=0` reports early `rc=134` aborts in `book/evidence/experiments/runtime-final-final/suites/shrink-trace/out/trace_min/phases/trace/metrics.jsonl`, then converges after rules are added. This points to a genuine loader boundary (a host characteristic), not just a tracing artifact.
- **Create vs truncate remains required after shrink**: the shrunk baseline profile keeps both `file-write-create` and `file-write-data` for `out/hello.txt` (see `book/evidence/experiments/runtime-final-final/suites/shrink-trace/out/shrink_twostate/profiles/shrunk.sb`). This reflects the sandbox's distinct write operations on this host, not a tooling quirk.
- **Required operations persist through shrink**: the required network rule remains in `book/evidence/experiments/runtime-final-final/suites/shrink-trace/out/shrink_net_required/profiles/shrunk.sb`, and child-process rules remain in `book/evidence/experiments/runtime-final-final/suites/shrink-trace/out/shrink_spawn/profiles/shrunk.sb`. These are necessary to preserve program semantics on this host.

### Ambiguous cases (need more evidence)

- **`no_new_rules` can mean two things**: it might indicate a fully-allowed program, or it might indicate missing deny capture. The mixed outcomes in `book/evidence/experiments/runtime-final-final/suites/shrink-trace/out/matrix/summary.json` (success vs `no_new_rules` under similar knobs) suggest log-capture variability that is not yet fully bounded.
- **PID scope not yet quantified**: we have not run a `DENY_SCOPE=pid` vs `DENY_SCOPE=all` comparison in the matrix, so we cannot yet quantify how much deny surface is attributable to child processes vs ambient noise.

Practical takeaway: treat convergence as a compound property. If a run ends `no_new_rules`, check whether a required operation is still failing and whether the deny stream is complete. If a run converges but produces a large `bad_rules` count or a very large trace profile, interpret it as partial evidence and use the matrix to locate stable baselines before trusting the shrink output.

## Evidence checklist

Trace evidence:
- `run.json` (world_id, knobs, and paths)
- `phases/trace/metrics.jsonl` (iterations, denies, new rules)
- `profiles/trace.sb` (the traced profile)
- `phases/trace/status.json` (stop reason)
- `phases/trace/logs/iter_<n>.log` or `phases/trace/logs/iter_<n>_log_show.json` (raw sandbox messages)
- `phases/trace/bad_rules.txt` (rejected rule candidates)

Shrink evidence:
- `profiles/shrunk.sb` (minimized profile)
- `phases/shrink/stdout.txt` (rule removals/keeps)
- `phases/shrink/metrics.jsonl` (per-candidate decisions)
- `phases/shrink/validation/post_shrink_fresh.json` and `phases/shrink/validation/post_shrink_repeat.json` (two-state validation)
- `phases/shrink/validation/lint.txt` (network filter sanity)
