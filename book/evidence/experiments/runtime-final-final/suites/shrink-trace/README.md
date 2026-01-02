# shrink-trace API (proposed)

This README describes the eventual API tool to be built from the shrink/trace workflow. It is an interface and behavior specification, not an experiment log.

## Purpose

Provide a host-bound tool that:
- Traces sandbox denials to bootstrap an SBPL allow profile.
- Shrinks a permissive profile to the smallest set of rules that still satisfies a defined success contract.

## Scope and assumptions

- Host-bound to `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
- macOS-only; depends on `sandbox-exec` and unified logging.
- SBPL profile syntax and semantics are treated as host-local and may change across OS versions.
- `sandbox-exec` is deprecated; this API documents a constrained, local tool that is expected to remain usable on the current host but is not promised across releases.

## Interface (planned)

### CLI surface

```
shrink-trace trace   --profile <sbpl> --cmd <exe> [--out <dir>] [--success-streak N] [--deny-scope all|pid]
shrink-trace shrink  --profile <sbpl> --cmd <exe> [--out <dir>]
shrink-trace workflow --cmd <exe> [--out <dir>] [--seed-dyld 0|1] [--import-dyld-support 0|1]
shrink-trace lint    --profile <sbpl>
shrink-trace summary --out <dir>
```

### Python API surface (planned)

```
trace_profile(command, profile_path, out_dir, *, success_streak=2, deny_scope="all")
shrink_profile(command, profile_path, out_dir)
workflow_profile(command, out_dir, **options)
lint_profile(profile_path)
```

## Behavioral contract

- **Trace convergence:** stop only after `success_streak` consecutive runs exit 0 and add 0 new rules on the final run(s). This ensures repeatable success under the same profile.
- **Shrink contract:** only remove a rule when both a fresh run and a repeat run succeed. This guards against first-run-only permissions (for example, create vs truncate).
- **Profile safety:** rule candidates should be parse-checked before committing to avoid profile-level failures.
- **Network normalization:** network rules should normalize host filters to `*` or `localhost` and treat path-shaped addresses as unix sockets.

## Inputs

- Executable path (no args in the initial tool; args can be added in a later revision).
- SBPL profile path (created if missing during `trace`).
- Output directory for logs, metrics, and derived profiles.
- Optional parameters (seed allowances, dyld import, deny scope, network rule mode).

## Outputs

- `run.json` (manifest: world_id, knobs, and key paths)
- `profiles/trace.sb` (traced profile)
- `profiles/shrunk.sb` (minimized profile)
- `phases/trace/status.json` and `phases/trace/metrics.jsonl` (trace outcome + per-iteration metrics)
- `phases/trace/stdout.txt` and `phases/trace/stderr.txt` (trace runner output)
- `phases/trace/logs/` (per-iteration unified logs and stdout/stderr)
- `phases/trace/bad_rules.txt` (rules rejected as invalid)
- `phases/shrink/status.json` and `phases/shrink/metrics.jsonl` (shrink outcome + per-candidate decisions)
- `phases/shrink/stdout.txt` and `phases/shrink/stderr.txt` (shrink runner output)
- `phases/shrink/validation/` (preflight, lint, and pre/post shrink run records)
- `artifacts/bin/` (fixture binaries for the run)
- `out/matrix/summary.json` (run matrix summary, when requested)

## Operational constraints

- Unified log access may require elevated log visibility (for example, Full Disk Access for the terminal).
- Trace relies on consistent sandbox log emission during the run window; if deny messages are missing, convergence can be brittle.
- The tool intentionally avoids `killall` side-effects in logging.

## Documentation

- `book/evidence/experiments/runtime-final-final/suites/shrink-trace/Examples.md` provides concrete, working examples with interpretations.
- Implementation lives in `book/tools/sbpl/trace_shrink/trace_shrink.py`; this experiment is the evidence harness.

## Glossary (API terms)

Primary concepts:

- **trace**: Build a profile by running a target under `sandbox-exec` and appending allow rules derived from observed denials.
- **shrink**: Minimize a profile by removing rules while preserving the success contract (fresh + repeat runs).

Primary artifacts:

- **profiles/trace.sb**: The traced SBPL profile produced by the trace phase.
- **profiles/shrunk.sb**: The minimized SBPL profile produced by the shrink phase.

Implementation terms:

- **success_streak**: Number of consecutive successful runs (rc==0) with no new rules required to declare trace convergence.
- **deny_scope**: Scope of deny extraction; `all` = any sandbox message in the run window, `pid` = only parent PID.
- **seed_dyld**: Whether to add a small loader seed to the initial profile to allow early dynamic loading.
- **import_dyld_support**: Whether to import the OS `dyld-support.sb` profile when present.
- **fresh run**: Execution after removing the output directory, representing a first-run state.
- **repeat run**: Execution without cleanup after a fresh run, representing steady-state behavior.
- **network_rules**: Mode for handling network denies: `parsed` (normalize to `*`/`localhost`), `drop`, or `coarse`.
- **phases/trace/bad_rules.txt**: Rules rejected because they cause profile parse/apply failures.
- **run.json**: Top-level manifest for a run (world_id, knobs, outcomes, and paths).
