# Inside (Codex harness sandbox detector)

This tool detects whether the current process is already sandboxed, so policy-facing runs do not misread harness gates as policy decisions.
It runs a small sensor set and returns a structured verdict with explicit evidence tiers and confidence.

Host baseline: `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.

## Evidence tiers

- **Mapped**: direct host observations (S0-S4, S6).
- **Hypothesis**: log corroboration (S5) because access is blocked under sandbox and noisy under elevated.

Bedrock surfaces (context only; this tool does not map ops/filters):
- `book/integration/carton/bundle/relationships/mappings/vocab/ops.json`
- `book/integration/carton/bundle/relationships/mappings/vocab/filters.json`
- `book/integration/carton/bundle/relationships/mappings/vocab/ops_coverage.json`

## Sensors and thresholds

Each sensor yields a result class: `strong_true`, `weak_true`, `unknown`, `weak_false`, `strong_false`.
"True" means the harness is constrained; "false" means unconstrained.

- S0 (self sandboxed)
  - `sandbox_check(getpid(), NULL, 0)`.
  - `rc == 1` => `strong_true`; `rc == 0` => `strong_false`.

- S1 (mach-lookup preflight)
  - `sandbox_check(getpid(), "mach-lookup", SANDBOX_FILTER_GLOBAL_NAME, <service>)`.
  - Uses vendored `SANDBOX_FILTER_GLOBAL_NAME` when headers are missing.
  - Includes a negative control mach service to catch blanket denies.
  - Unfiltered fallback is allowed by default, but downgraded to weak.

- S2 (bootstrap sentinel)
  - `bootstrap_look_up` against 2+ service names.
  - `kr == 1100` => `strong_true`; `kr == 0` => `weak_false`.

- S3 (PolicyWitness sentinel)
  - `policy-witness xpc run --profile minimal fs_op --op stat --path-class tmp`.
  - `xpc:openSession_failed` with sandbox restriction => `strong_true`.
  - Missing binary, parse errors, timeouts => `unknown`.

- S4 (SBPL apply heuristic)
  - Run wrapper with allow-all SBPL in a subprocess.
  - Apply-stage EPERM => `strong_true`; apply ok => `weak_false`.
  - Off by default; enable with `--include-apply`.

- S5 (log corroboration, optional)
  - `log show --start <t0> --end <t1> --predicate ...`.
  - PID-matched deny lines => `weak_true`; failures => `unknown`.
  - Off by default; enable with `--with-logs`.

- S6 (App Sandbox metadata)
  - Check `APP_SANDBOX_CONTAINER_ID` and `HOME` container path.
  - Reported as metadata (axis `app_sandbox`), not used in harness scoring.

## Scoring model

The tool answers: "Is the harness already constrained such that policy measurements are suspect?"

Rules:
- Any `strong_true` in S0/S2/S4 => `harness_constrained=true` with `confidence=high`.
- Two or more `weak_true` across S1/S3/S5 => `true`, `confidence=medium`.
- All unknown => `harness_constrained=null`, `confidence=low`.
- Otherwise => `false`, `confidence=medium` (upgraded to high if S0 is `strong_false` and S2 is `weak_false`).

## Usage

From repo root:

```sh
python3 book/tools/inside/inside.py
python3 book/tools/inside/inside.py --json
python3 book/tools/inside/inside.py --include-apply
python3 book/tools/inside/inside.py --with-logs
```

Key flags:
- `--json`: emit JSON only.
- `--include-apply`: enable S4 (apply heuristic).
- `--with-logs`: enable S5 log corroboration.
- `--log-bin`: override the log binary (defaults to `/usr/bin/log`).
- `--no-unfiltered`: disable unfiltered S1 fallback.
- `--disable-vendored`: do not use vendored filter constants.

## Output

JSON output includes:
- `summary.harness_constrained` and `summary.confidence`.
- Per-sensor results with `result_class`, `strength`, `direction`, and raw evidence fields.
- Repo-relative tool paths for PolicyWitness and SBPL wrapper/profile.

A one-line summary is printed in non-JSON mode:

```
INSIDE_SANDBOX_DETECT: constrained=true confidence=high triggers=S0,S2
```
