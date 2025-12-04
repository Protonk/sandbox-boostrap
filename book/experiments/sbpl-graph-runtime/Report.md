# SBPL ↔ Graph ↔ Runtime – Research Report (Sonoma 14.4.1, arm64, SIP on)

## Aim
Produce SBPL → PolicyGraph → runtime “golden triples” on the Sonoma host, with expectation-aligned runtime logs (schema: provisional) keyed by `expectation_id`. Golden profiles must have coherent SBPL, decoded graphs, and runtime outcomes via `sandbox_init` from an unsandboxed caller.

## Current status (provisional cut)
- Golden triples (custom, allow-default, file-centric): `runtime:allow_all`, `runtime:metafilter_any`, `bucket4:v1_read`. SBPL is simple; decoded graphs match intent; static expectations carry expectation_ids; runtime results match expectations (OS perms on `/etc/hosts` writes are noted as outside sandbox scope).
- Tooling: new `book/api/golden_runner` API/CLI (with unit tests) now emits compiled blobs, ingested summaries, static expectations, and runtime logs straight into the golden profiles folder; the experiment’s `run_probes.py` is now just a thin wrapper over this API.
- Platform-only apply-gated: `sys:bsd`, `sys:airlock`, `sys:sample` return EPERM/execvp at apply even unsandboxed; treated as platform-only, not harness bugs.
- Custom outlier: `bucket5:v11_read_subpath` still blocked with EPERM on deny probes; non-golden.
- Strict/apply-gate outliers: `runtime:param_path_concrete` and `runtime:param_path_bsd_bootstrap` remain blocked at runtime; no strict profile is promoted in this cut.

## Where artifacts now live
- Golden profiles and outputs are persisted under `book/profiles/golden-triple/`:
  - SBPL sources (originals remain under experiments), compiled blobs, ingested summaries (`ingested.json`), static expectations (`static_expectations.json`, schema: provisional), runtime logs (`runtime_results.json`), manifest (`triples_manifest.json`).
  - Expected matrix for golden probes: `book/profiles/golden-triple/expected_matrix.json`.
- Experiment `out/` files have been trimmed to the golden set and remain as scratch.
- Platform-only and strict/apply-gate profiles stay quarantined in experiments.

## Plan
- Treat this provisional cut as the locked golden set on Sonoma 14.4.1. No further work unless expanding scope (e.g., strict profiles) in a separate experiment.
- Keep platform-only and strict/apply-gate cases documented as outliers; do not promote until runtime aligns with static expectations.

## Status/Risk notes
- Golden profiles validated on this host; OS-level permissions (e.g., `/etc/hosts` writes) are outside sandbox scope and noted as such.
- Platform profiles are apply-gated by design; retain as platform-only examples.
- Strict/apply-gate profiles are known to fail runtime on this host; future strict work, if needed, should be run as a separate experiment branch.
