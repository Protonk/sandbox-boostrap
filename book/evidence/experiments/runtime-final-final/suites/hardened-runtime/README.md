# Hardened Runtime

## What this is
`hardened-runtime` is the clean, provenance-stamped decision-stage runtime lane for non-VFS sandbox operations on the Sonoma 14.4.1 baseline. It produces baseline, scenario, and oracle artifacts under a launchd clean channel so downstream tooling can rely on stable, host-bound evidence without inheriting a sandboxed parent.

## What this is not
- It is not a VFS canonicalization or path-alias experiment. Path observations are recorded only as context.
- It is not a bypass or exploit lane.
- It does not use `sandbox-exec` (deprecated); all policy application uses `sandbox_init` via the shared `sandbox_runner`.

## How to run
Use the clean launchd channel so policy application is not nested:

```sh
python -m book.api.runtime status
python -m book.api.runtime plan-lint --plan book/evidence/experiments/runtime-final-final/suites/hardened-runtime/plan.json
python -m book.api.runtime run \
  --plan book/evidence/experiments/runtime-final-final/suites/hardened-runtime/plan.json \
  --channel launchd_clean \
  --out book/evidence/experiments/runtime-final-final/suites/hardened-runtime/out
```

## Outputs and how to read them
The run emits artifacts under `book/evidence/experiments/runtime-final-final/suites/hardened-runtime/out/<run_id>/` and updates `book/evidence/experiments/runtime-final-final/suites/hardened-runtime/out/LATEST`. Every JSON artifact carries a `schema_version`. The canonical entrypoint is the Artifact Index:

- `artifact_index.json` lists file paths, digests, schema versions, and producer metadata.
- `run_manifest.json` records channel, world id, staging root, and apply-preflight context.
- `baseline_results.json` records unsandboxed baseline outcomes.
- `runtime_results.json` records sandboxed outcomes and per-probe decision metadata.
- `runtime_events.normalized.json` is the normalized decision-stage event stream.
- `oracle_results.json` captures sandbox-check callouts (oracle lane only).
- `mismatch_packets.jsonl` captures bounded mismatches with explicit reasons.
- `summary.json` / `summary.md` provide a quick status overview.

Key lanes:
- **baseline**: unsandboxed runs only.
- **scenario**: sandboxed decision-stage runs.
- **oracle**: sandbox_check callouts (never merged into syscall-observed evidence).

## Signal canary (important semantic note)
The signal canary uses a **same-sandbox child process** as the target. The profiles are named `signal_self_*`, but the deny control uses `target same-sandbox` because `self` is not a meaningful deny control on this host. The probe emits a `probe_details` block that includes child pid, handshake status, and whether the signal was delivered.

## Adding a new probe family
1. Add SBPL profiles under `sb/`:
   - A strict profile (`deny default`) for negative controls.
   - A canary profile (`allow default`) with `(allow <op> (with report))` for positive evidence.
2. Add probes under `probes/` and register them in `registry/probes.json` + `registry/profiles.json`.
3. Run the plan via the clean channel to produce artifacts.
4. Refresh the preflight index: `python book/tools/preflight/build_index.py`.
5. Update `Report.md` / `Notes.md` to record what changed and what remains partial.

## Decision-path metadata
Each probe record includes `primary_intent`, `decision_path`, `first_denial_op`, and `first_denial_filters` to distinguish primary-op denies from dependency denies. These fields are always present, even when runs are `ok`.
