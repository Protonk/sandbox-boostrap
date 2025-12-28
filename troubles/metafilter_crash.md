# Metafilter runtime crash (`runtime:metafilter_any`)

## Context

- Host: Sonoma baseline (see `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5 (baseline: book/world/sonoma-14.4.1-23E224-arm64/world.json)`).
- Experiment: `book/experiments/sbpl-graph-runtime` (profile `profiles/metafilter_any.sb`).
- Harness: `sandbox_runner` driven by `book/experiments/runtime-checks/run_probes.py`.
- Probes: read `/tmp/foo.txt`, `/tmp/bar.txt` (expected allow), `/tmp/other.txt` (expected deny).

## Symptom

- Runs against `runtime:metafilter_any` exit with `-6` (SIGABRT) for the “allowed” reads and record `actual=deny`.
- The deny case matches expectations, but there is no useful stderr output from the runner.

## Reproduction

- Enable the `runtime:metafilter_any` profile entry in `run_probes.py` and run the `runtime-checks` harness on this Sonoma host.
- With the original profile shape:
  ```scheme
  (version 1)
  (deny default)
  (allow file-read* (require-any (literal "/tmp/foo.txt") (literal "/tmp/bar.txt")))
  ```
  the crash reproduces reliably.

## Investigation

1. **Profile simplification**
   - Switched from an allow-default/deny-not-any form to the straightforward deny-default + allow-if-require-any profile above.
   - Recompiled (`metafilter_any.sb.bin`) and reran probes; allowed reads still exited with `-6`.

2. **Runtime shim check**
   - The runtime profile includes process-exec and basic file-read metadata shims with `/tmp/foo` allowances; there were no explicit shim literals for `.txt` paths.
   - The shim was not intended to block the allows; no write denies were present in this profile.

3. **Harness sanity**
   - Other profiles (`allow_all`, bucket-4, bucket-5) ran cleanly under the same runner, suggesting the crash was specific to this profile shape rather than the harness itself.

4. **Additional shims**
   - Added explicit shim rules to allow `/tmp/foo.txt` and `/tmp/bar.txt`, then recompiled with the deny-default + require-any profile.
   - Crash persisted: allowed paths exited `-6` with no stderr, deny path exited `-6` and recorded deny.

## Status and interpretation

- Status: **resolved** for this host and harness.
- Root cause was a combination of:
  - insufficient allowances for `/tmp` vs `/private/tmp` path resolution under this host’s layout, and
  - the use of an exec-based reader in the probes.
- The fix:
  - switched the probes for this case to a non-exec reader (`sandbox_reader`), and
  - expanded the metafilter to include both `/tmp/*` and `/private/tmp/*` literals in the profile.
- With these changes, runtime probes now behave as intended: reads of `/tmp/foo.txt` and `/tmp/bar.txt` succeed (exit 0), and `/tmp/other.txt` is denied with `EPERM`.
- Remaining work on metafilters (for system profiles and more complex shapes) lives in the `sbpl-graph-runtime` and `runtime-checks` experiments; there is no outstanding metafilter-specific crash.

## Pointers

- Profile: `book/experiments/sbpl-graph-runtime/profiles/metafilter_any.sb`
- Harness: `book/experiments/runtime-checks/run_probes.py`
- Reader helper: `book/experiments/runtime-checks/sandbox_reader` (non-exec probe path)
