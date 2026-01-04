# trace_shrink

Role: host-bound trace + shrink harness for SBPL profiles on the fixed Sonoma baseline.

This tool wraps the `shrink-trace` experiment logic in a stable, reusable CLI while keeping
outputs compatible with the experiment’s evidence layout.

World: `world_id sonoma-14.4.1-23E224-arm64-dyld-a3a840f9`.

## Usage

From repo root:

```sh
# Trace + shrink (the full workflow)
python3 book/tools/sbpl/trace_shrink/trace_shrink.py workflow

# Trace only (build profile from denials)
python3 book/tools/sbpl/trace_shrink/trace_shrink.py trace

# Shrink only (minimize an existing trace profile in the output dir)
python3 book/tools/sbpl/trace_shrink/trace_shrink.py shrink --no-clean
```

Common knobs (also available via env vars):

```sh
OUT_DIR=book/evidence/experiments/runtime-final-final/suites/shrink-trace/out \
FIXTURE_BIN=sandbox_target \
IMPORT_DYLD_SUPPORT=1 \
NETWORK_RULES=parsed \
SUCCESS_STREAK=2 \
python3 book/tools/sbpl/trace_shrink/trace_shrink.py workflow
```

## Output layout

Each run writes a standardized tree under `OUT_DIR`:

- `run.json` (world_id + knobs + outcome manifest, including timing)
- `profiles/trace.sb` (traced profile)
- `profiles/shrunk.sb` (minimized profile)
- `phases/trace/` (status.json, metrics.jsonl, logs, bad_rules.txt)
- `phases/shrink/` (status.json, metrics.jsonl, validation records)
- `artifacts/bin/` (fixture binaries)

The tool runs `book/tools/preflight/preflight.py` before shrink, and lints profiles using
`book/evidence/experiments/runtime-final-final/suites/shrink-trace/scripts/lint_profile.py`.

## Notes

- This tool depends on `sandbox-exec` and unified logging; it is host-bound and macOS-only.
- Apply-gate failures are treated as blocked evidence; see `book/tools/preflight/README.md`.
