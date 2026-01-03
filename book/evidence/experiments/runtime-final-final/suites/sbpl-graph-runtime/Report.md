# SBPL ↔ Graph ↔ Runtime – Research Report

## Aim
Produce SBPL → PolicyGraph → runtime “golden triples” on the Sonoma host, with expectation-aligned runtime logs (schema: provisional) keyed by `expectation_id`. Golden profiles must have coherent SBPL, decoded graphs, and runtime outcomes via `sandbox_init` from an unsandboxed caller.

## Current status (provisional cut)
- Golden triples (custom, allow-default, file-centric): `runtime:allow_all`, `runtime:metafilter_any`, `bucket4:v1_read`, plus minimal strict profile `runtime:strict_1`. SBPL mode via `runtime` aligns runtime with expectations (OS perms on `/etc/hosts` writes are outside sandbox scope). Wrapper “no version specified” errors on blobs are avoided by using SBPL inputs.
- Tooling: new `book/api/golden_runner` API/CLI (with unit tests) now emits compiled blobs, ingested summaries, static expectations, and runtime logs straight into the golden profiles folder; the experiment’s `run_probes.py` is now just a thin wrapper over this API.
- Platform-only apply-gated: `sys:bsd`, `sys:airlock`, `sys:sample` return EPERM/execvp at apply even unsandboxed; treated as platform-only, not harness bugs.
- Custom outlier: `bucket5:v11_read_subpath` still returns `EPERM` on the expected-allow probe (`/tmp/foo`), so status stays `partial`/non-golden.
- Strict/apply-gate notes: legacy strict candidates (`runtime:param_path_concrete`, `runtime:param_path_bsd_bootstrap`) remain blocked; a minimal strict profile (`runtime:strict_1`) now runs cleanly in SBPL mode.
- Parameterized SBPL (host-bound): compile-time params-handle compilation is now validated for a minimal `(param ...)` profile, and the golden-triple matrix includes a blob-mode runtime witness (`runtime:param_deny_root_ok`) that denies `file-read*` under a parameterized ROOT. Deny-default + exec-based blob probes remain brittle (SIGABRT) for now, so blob-mode parameterization uses `allow default` as the stable carrier.

### Bucket5 divergence (tied to VFS canonicalization)

- Decode shows `bucket5:v11_read_subpath` embeds `/tmp/foo` (no `/private/tmp/foo`), while the canonical runtime path for `/tmp/foo` is `/private/tmp/foo`. `runtime:strict_1` embeds the canonical `/private/tmp/strict_ok` and succeeds; `bucket4:v1_read` is path-agnostic. The remaining `EPERM` on `bucket5` is therefore an explained divergence: the literal does not match the canonicalized path.
- Status remains `partial` by design; do not treat it as flaky. The same `/tmp` → `/private/tmp` behavior is documented in `book/evidence/experiments/runtime-final-final/suites/vfs-canonicalization/Report.md`.
- Literal/node details: decoded nodes show `bucket5` references `Ftmp/foo` at node offsets 192 (tag 0) and 264 (tag 6), but there is no `/private/tmp/foo` literal in the pool. `strict_1` includes `/private/tmp/strict_ok` in its literal pool (plus `/etc/hosts` denies and shim anchors). `bucket4` carries no path literals. This is consistent with the canonicalization story and explains the deny on the `/tmp/foo` allow probe.

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
