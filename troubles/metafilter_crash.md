# Metafilter Runtime Crash (runtime:metafilter_any)

## Error

- Profile: `book/experiments/sbpl-graph-runtime/profiles/metafilter_any.sb`
- Runtime harness: `sandbox_runner` via `book/experiments/runtime-checks/run_probes.py`
- Probes: read `/tmp/foo.txt`, `/tmp/bar.txt` (expected allow), `/tmp/other.txt` (expected deny).
- Result: allowed reads exit with `-6` (SIGABRT) and `actual=deny`, deny case matches. No stderr output from the runner.

## What was tried

1) **Simplified profile**
   - Switched from an allow-default/deny-not-any form to a straightforward deny-default + allow-if-require-any:
     ```
     (version 1)
     (deny default)
     (allow file-read* (require-any (literal "/tmp/foo.txt") (literal "/tmp/bar.txt")))
     ```
   - Recompiled (`metafilter_any.sb.bin`) and reran probes. Crash persists (exit -6 on allowed reads).

2) **Runtime shim check**
- Runtime profile includes process-exec + basic file read metadata shims and `/tmp/foo` read allowances. No explicit literals for `.txt` paths added. The shim is not supposed to block allows; write denies are not present here.

3) **Harness sanity**
   - Other profiles (`allow_all`, bucket4/5) run fine under the same runner, so the crash seems specific to this profile shape.

## Next options

- Add explicit shim allows for the literal `.txt` paths to rule out shim-side issues:
  ```
  (allow file-read* (literal "/tmp/foo.txt"))
  (allow file-read* (literal "/tmp/bar.txt"))
  ```
- Decode `metafilter_any.sb.bin` to inspect node layout and ensure the require-any encoding matches expectations; check for unsupported filter kinds or missing literals.
- Try a control profile without metafilter (just two literal allows) to confirm runner stability.
- If crashes persist, add runner logging or run under lldb to capture the abort reason.

## Latest attempt (with shims for literals)
- Added shim rules to explicitly allow `/tmp/foo.txt` and `/tmp/bar.txt` in the runtime profile; recompiled profile with deny-default + allow require-any.
- Crash persists: reads to allowed paths exit -6 with no stderr, deny path exits -6 and records deny. Runtime harness appears fine for other profiles, so the abort is likely profile/decoder related.

## Resolution (current)
- Root cause was insufficient allowances + `/tmp` vs `/private/tmp` path resolution. Switched `file-read*` probes to a non-exec reader (`sandbox_reader`) and expanded the metafilter to include both `/tmp/*` and `/private/tmp/*` literals. Runtime probes now succeed: foo/bar allowed (exit 0), other denied (EPERM).
- Remaining tasks: investigate system profiles; no further metafilter crash.
