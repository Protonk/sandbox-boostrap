# Entitlement Diff – Notes

## Reset for EntitlementJail 1.x
- Legacy jail outputs and runners removed; use `run_entitlementjail.py` for new captures.

## Quick commands
- `python book/experiments/entitlement-diff/run_entitlementjail.py --scenario inventory`
- `python book/experiments/entitlement-diff/run_entitlementjail.py --scenario matrix`
- `python book/experiments/entitlement-diff/run_entitlementjail.py --scenario bookmarks`
- `python book/experiments/entitlement-diff/run_entitlementjail.py --scenario downloads_rw`
- `python book/experiments/entitlement-diff/run_entitlementjail.py --scenario net_client`
- `python book/experiments/entitlement-diff/run_entitlementjail.py --scenario net_op_groups`

## Reminders
- Use `probe_catalog` outputs to confirm probe availability (bookmark probes are not assumed).
- `--log-sandbox` capture is best-effort; absence of deny lines is not a sandbox claim.
- Keep EntitlementJail outputs under `book/experiments/entitlement-diff/out/ej/`.

## EntitlementJail 1.x inventory run
- Command: PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario inventory
- Result: inventory.json written, but all EntitlementJail subcommands exited with rc=-6 and no stderr; health-check/list-profiles/show-profile/describe-service did not return output.
- Status: blocked (EntitlementJail CLI exits rc=-6 before responding)
- Follow-up: run the CLI directly to capture any usage output or crash behavior; check for external crash logs if needed.

## EntitlementJail CLI under harness sandbox
- Command: book/tools/entitlement/EntitlementJail.app/Contents/MacOS/entitlement-jail --help
- Result: sandbox aborted the process with Signal 6 before any output.
- Follow-up: run EntitlementJail commands with escalated permissions; unprivileged runs appear to abort in this harness.

- Command: book/tools/entitlement/EntitlementJail.app/Contents/MacOS/entitlement-jail list-profiles (escalated)
- Result: succeeds and returns profiles JSON; indicates the CLI itself is functional when run outside the harness sandbox restrictions.
- Status: ok (entitlement-jail usable with escalation)

## Inventory capture (escalated)
- Command: PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario inventory (escalated)
- Result: inventory.json written with 11 commands; all exit_code=0.
- Status: ok

## Matrix run (initial failure)
- Command: PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario matrix (escalated)
- Result: run-matrix exit_code=2; stderr reports failure to remove the repo output dir with Operation not permitted.
- Status: blocked (EntitlementJail sandbox cannot remove/write to repo path)
- Follow-up: reroute run-matrix to its default output directory and copy results into repo.

## Matrix run (runner fix)
- Command: PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario matrix (escalated)
- Result: runner failed with SyntaxError in run_entitlementjail.py (bad escape in $HOME hint); fixed to f"$HOME/{rel}".
- Status: resolved (script updated)
- Command: PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario matrix (escalated)
- Result: runner failed with SyntaxError from escaped quotes in source_dir definition; fixed to use normal quotes.
- Status: resolved (script updated)

- Result: matrix.json exit_code=0 but copy_error indicates source_missing at $HOME/Library/Application Support/entitlement-jail/matrix/latest.
- Observation: run-matrix outputs live under the app container at $HOME/Library/Containers/com.yourteam.entitlement-jail/Data/Library/Application Support/entitlement-jail/matrix/latest.
- Follow-up: update runner to copy from the container path first, with fallback to the non-container path.

## Matrix capture (escalated, container source)
- Command: PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario matrix (escalated)
- Result: run-matrix exit_code=0; outputs copied from container matrix/latest into book/experiments/entitlement-diff/out/ej/matrix/baseline.
- Status: ok

## Bookmarks run (initial failure)
- Command: PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario bookmarks (escalated)
- Result: fs_op and bookmark_make runs exited rc=2 with stderr "--profile cannot be combined with an explicit service id"; probe_catalog/world_shape/capabilities_snapshot succeeded.
- Diagnosis: EntitlementJail run-xpc accepts --profile for simple probes, but fs_op with args fails; explicit service bundle id works for fs_op.
- Follow-up: update runner to use explicit service_id for run-xpc probes (retain profile_id only as metadata).

- Result: bookmark_make under minimal returned rc=1 (expected missing entitlement), but log_capture failed because the repo log path is not writable from EntitlementJail; log_capture_path points at the repo and fails with "folder doesn't exist".
- Follow-up: update runner to capture logs under the EntitlementJail container tmp dir and copy into repo after each run.

## Bookmarks capture (service ids + container log capture)
- Command: PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario bookmarks (escalated)
- Result: runs completed; minimal bookmark_make returns rc=1 with normalized_outcome=bookmark_make_failed and service_refusal=entitlement_missing_bookmarks_app_scope (expected entitlement gap). Log files copied into book/experiments/entitlement-diff/out/ej/logs.
- Status: ok (partial runtime evidence; deny evidence depends on log contents)

## Downloads RW capture
- Command: PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario downloads_rw (escalated)
- Result: minimal fs_op listdir returns rc=1 with normalized_outcome=permission_error; downloads_rw fs_op returns ok. Log capture requested but failed with `log: Cannot run while sandboxed` for both services; log files are present but represent failed capture.
- Status: ok (partial runtime evidence; deny evidence blocked by sandboxed log)

## Net client capture
- Command: PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario net_client (escalated)
- Result: minimal net_op tcp_connect returns rc=1 with normalized_outcome=permission_error and listener timeout; net_client returns ok with listener accepted. Log capture failed with `log: Cannot run while sandboxed` for both.
- Status: ok (partial runtime evidence; deny evidence blocked by sandboxed log)

## Evidence & inspection capture
- Command: PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario evidence (escalated)
- Result: verify-evidence and inspect-macho commands exit_code=0; bundle-evidence copied from container path into book/experiments/entitlement-diff/out/ej/evidence/latest.
- Status: ok

## Matrix groups capture
- Command: PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario matrix_groups --ack-risk fully_injectable (escalated)
- Result: baseline/debug/inject/jit groups exit_code=0 with copied outputs under book/experiments/entitlement-diff/out/ej/matrix/<group>/.
- Status: ok

## Probe families (initial fs_xattr failure)
- Command: PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario probe_families (escalated)
- Result: fs_xattr set/get/list returned normalized_outcome=not_found; fs_op create reported file_path as the run_dir rather than a file path.
- Status: blocked for fs_xattr (target path mismatch)
- Follow-up: switch fs_op create to --target specimen_file so details.file_path points at a file; rerun probe_families.

- Result: fs_xattr still returned normalized_outcome=not_found after switching to specimen_file; fs_op create produced a run_dir file path, but fs_xattr could not find it (likely per-run temp cleanup).
- Follow-up: switch fs_op create target to harness_dir for a stable file path, then rerun probe_families.

- Result: fs_op create with target=harness_dir failed (op_failed; harness_dir is a directory and --name is ignored). fs_xattr could not proceed.
- Follow-up: switch fs_op create target to base (tmp root) to create a stable file path; rerun probe_families.

- Result: fs_xattr set refused with bad_request: "refusing xattr write on non-harness path"; get reported attribute absent.
- Follow-up: add --allow-write to fs_xattr set and rerun probe_families.

## Probe families capture (resolved)
- Command: PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario probe_families (escalated)
- Result: userdefaults_op write/read/remove ok; fs_xattr set/get/list ok after allowing write; fs_coordinated_op read/write ok.
- Status: ok

## Bookmark roundtrip capture
- Command: PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario bookmark_roundtrip (escalated)
- Result: bookmark_roundtrip supported; minimal roundtrip_stat returns bookmark_make_failed with service_refusal=entitlement_missing_bookmarks_app_scope; bookmarks_app_scope roundtrip succeeds.
- Status: ok (partial runtime evidence; deny evidence depends on log capture)

## Log capture status for new scenarios
- Runner updated to request `--log-stream` (host path) and capture observer output under `out/ej/logs/observer/`; rerun needed to see whether deny evidence is captured.
- Command: PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario downloads_rw
- Result: log stream files written under `book/experiments/entitlement-diff/out/ej/logs/`; observer reports written under `book/experiments/entitlement-diff/out/ej/logs/observer/`; no sandbox deny lines observed for downloads_rw runs.
- Command: PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario net_client
- Result: log stream captured a sandbox deny line for minimal tcp_connect (`net_client.minimal.tcp_connect.log`); observer report for the same run reports `observed_deny: true`.
- Command: PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario bookmarks
- Result: log stream captured a sandbox deny for minimal bookmark_make (`bookmarks.minimal.bookmark_make.log`); observer report for the same run reports `observed_deny: true`. Non-target processes also emitted sandbox logs in this capture; do not treat those as ProbeService denials.
- Command: PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario probe_families
- Result: log stream and observer reports captured; no sandbox deny lines observed for userdefaults/fs_xattr/fs_coord probes.
- Command: PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario bookmark_roundtrip
- Result: log stream captured a sandbox deny for minimal roundtrip_stat (`bookmark_roundtrip.minimal.roundtrip_stat.log`); observer report for the same run reports `observed_deny: true`.
- Command: PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario wait_attach
- Result: log stream + observer captured for capabilities_snapshot; no sandbox deny lines observed in wait_attach logs.
- Command: PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario wait_timeout_matrix
- Result: log stream captured; no sandbox deny lines observed in wait_timeout logs.
- Command: PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario wait_path_class
- Result: log stream + observer captured for capabilities_snapshot; no sandbox deny lines observed.
- Command: PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario wait_multi_trigger
- Result: log stream captured; no sandbox deny lines observed in wait_multi logs.
- Command: PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario wait_probe_wait
- Result: log stream captured; no sandbox deny lines observed in wait_probe logs.
- Command: PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario wait_hold_open
- Result: log stream + observer captured for capabilities_snapshot; no sandbox deny lines observed.
- Command: PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario wait_create
- Result: log stream + observer captured for capabilities_snapshot; no sandbox deny lines observed.
- Command: PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario wait_interval
- Result: log stream + observer captured for capabilities_snapshot; no sandbox deny lines observed.
- Command: PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario attach_holdopen_default
- Result: log stream + observer captured for capabilities_snapshot; no sandbox deny lines observed in attach_default logs.
- Command: PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario matrix_groups --ack-risk fully_injectable
- Result: matrix outputs refreshed under `book/experiments/entitlement-diff/out/ej/matrix/<group>/`; run-matrix does not request log capture, so no new deny evidence for this run.
- Command: PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario net_op_groups
- Result: log stream + observer captured for all probe profiles via net_op tcp_connect; observer reports `observed_deny: true` for `minimal`, `plugin_host_relaxed`, and `user_selected_executable`, and `observed_deny: false` for other probe profiles.
- EntitlementJail update notes (CLI help):
  - `run-xpc --help` now lists `--log-stream` and `--log-path-class` only; `--log-sandbox` is no longer present.
  - `sandbox-log-observer --help` now accepts `--plan-id`, `--row-id`, and `--correlation-id`.
- Command: PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario matrix_groups --ack-risk fully_injectable
- Result: matrix outputs refreshed; run-matrix still reports `group_id` as `jit` and lists the same profile set for all groups.
- Command: PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario net_client
- Result: observer report now includes `plan_id`, `row_id`, and `correlation_id` (verified in `book/experiments/entitlement-diff/out/ej/logs/observer/net_client.minimal.tcp_connect.log`).
- Runner update: sandbox-log-observer is now invoked for all runs by default, with `plan_id`/`row_id`/`correlation_id` forwarded when present.
- Command: PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario net_client
- Result: observer output now records non-null `start`/`end` fields and includes correlation metadata in `book/tools/entitlement/fixtures/contract/observer.sample.json` (moved from the experiment contract output).
- Observation: probe_families and bookmark_roundtrip runs report log_capture_status=requested_failed with `log: Cannot run while sandboxed` across all runs; deny evidence is not captured for these scenarios.
- Status: partial (runtime outcomes recorded, log capture blocked by sandboxed log invocation)

## Wait/attach workflow (iteration)
- Command: PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario wait_attach
- Result: initial run timed out at the harness level; wait/attach runner was still using --attach 20 and did not append probe args to run-xpc, which led to bad_request for fs_op and a BrokenPipe when triggering the FIFO.
- Fixes: added probe_args to the wait runner, recorded row_id/service/probe metadata, reduced --attach to 5, and ensured the wait process is terminated after timeout.

## Wait/attach capture (resolved)
- Command: PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario wait_attach
- Result: attach FIFO, explicit --wait-fifo, and --wait-exists runs all exit_code=0; wait-ready lines captured and triggers executed without error. Log capture still reports `log: Cannot run while sandboxed`.
- Status: ok (partial runtime evidence; deny evidence blocked by sandboxed log)

## Wait/attach timeout matrix
- Command: PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario wait_timeout_matrix
- Result: wait-exists runs with trigger_delay < wait_timeout_ms exit_code=0; trigger_delay > wait_timeout_ms exit_code=1. wait-ready lines report mode=exists. Log capture status is requested_failed with `log: Cannot run while sandboxed`.
- Status: ok (partial runtime evidence; timeout behavior observed, log capture blocked)

## Wait/attach path-class and wait-name (iteration)
- Command: PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario wait_path_class (path-class only)
- Result: exit_code=2 with stderr `missing --wait-fifo/--wait-exists (required when wait options are provided)`.
- Follow-up: rerun with explicit --wait-exists path plus --wait-path-class/--wait-name.
- Result: exit_code=2 with stderr `--wait-path-class/--wait-name cannot be combined with an explicit wait path`.
- Status: blocked (no compatible arg combo for wait-path-class + wait-name found)

## Wait/attach multi-trigger
- Command: PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario wait_multi_trigger
- Result: primary FIFO trigger ok; post-trigger nonblocking write fails with `OSError: [Errno 6] Device not configured`. wait-exists primary/post triggers ok. Log capture still requested_failed.
- Status: ok (partial; FIFO post-trigger shows no reader after run)

## Probe-level wait (fs_op_wait)
- Command: PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario wait_probe_wait
- Result: fs_op_wait fifo/exists exit_code=0; no wait-ready line emitted for probe-level wait. Log capture still requested_failed.
- Status: ok (partial runtime evidence; probe wait works without wait-ready line)

## Attach + hold-open
- Command: PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario wait_hold_open
- Result: wait-ready line emitted for FIFO; duration ~3.1s with --hold-open 3; exit_code=0. Log capture still requested_failed.
- Status: ok (partial runtime evidence; hold-open timing observed)

## EntitlementJail 1.x rerun after doc + app updates
- Commands: re-ran inventory, evidence, matrix_groups (with --ack-risk fully_injectable), bookmarks, downloads_rw, net_client, probe_families, bookmark_roundtrip, and all wait scenarios via run_entitlementjail.py.
- Result: all scenarios ran without escalation and reproduced prior outcomes (bookmark_make failure under minimal, downloads/net_client permission_error under minimal, probe_families ok, bookmark_roundtrip negative witness under minimal).
- Change: wait-path-class now works with `--wait-path-class tmp --wait-name ...` (exit_code=0, wait-ready line emitted) and no longer requires explicit wait path.
- Change: fs_op_wait now emits a wait-ready line for both fifo and exists runs.
- Log capture: still requested_failed with `log: Cannot run while sandboxed` across reruns.

## Log capture path-class follow-up
- Change: switched log capture to `--log-path-class tmp --log-name <...>` and reran all scenarios using `--profile` selection.
- Result: log capture still fails, now with `log_capture_error=write_failed` (`Operation not permitted`) when writing under the service container tmp dir; log_capture_path is present but the file is missing at copy time.
- Status: blocked for deny evidence capture (path-class avoids repo path issues but still cannot write capture file).

## Wait-create (FIFO auto-create)
- Command: PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario wait_create
- Result: --wait-create created a FIFO under the service tmp dir; wait-ready line emitted; trigger released the wait and exit_code=0; post-run stat shows FIFO still present.
- Status: ok (partial runtime evidence; log capture still blocked)

## Wait-interval for wait-exists
- Command: PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario wait_interval
- Result: wait-exists runs exit_code=0; data.details.wait_interval_ms reflects the supplied 25 and 250 values.
- Status: ok (partial runtime evidence)

## Attach default hold-open behavior
- Command: PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario attach_holdopen_default
- Result: --attach 3 without explicit hold-open runs ~3.2s; --attach 3 --hold-open 0 returns quickly (~0.2s).
- Status: ok (partial runtime evidence)

## Health-check per profile
- Command: PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario health_check_profile
- Result: health-check succeeds for both minimal and debuggable with exit_code=0.
- Status: ok

## run-matrix --out
- Command: PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario run_matrix_out
- Result: run-matrix baseline succeeded with --out set to the app container tmp dir; run-matrix.json data.output_dir matches the supplied path; outputs copied into out/ej/matrix/out_baseline.
- Status: ok

## bundle-evidence --out + --include-health-check
- Command: PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario bundle_evidence_out
- Result: bundle-evidence succeeded with --out set to the app container tmp dir; stdout JSON data.output_dir matches the supplied path; outputs copied into out/ej/evidence_out.
- Status: ok

## Quarantine lab text payload
- Command: PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario quarantine_lab
- Result: quarantine_default bundle id resolved via show-profile; quarantine-lab text payload run succeeded with exit_code=0.
- Status: ok (partial runtime evidence; no execution)

## EntitlementJail update: observer + stream
- Updated CLI help now exposes `--observe`/`--observer-*` and `--log-stream <path|auto|stdout>`, plus `sandbox-log-observer --duration/--follow --format --output`.
- `run-xpc` with `--log-stream` now emits `data.log_observer_*` and writes a `.log.observer.json` file (embedded observer report); log stream output is `sandbox_log_stream_report`.
- `--observe --observer-duration 2 --observer-format jsonl` produced a stream-mode observer report (`mode=stream`, `duration_ms=2000`) and a JSONL output file under `$HOME/Library/Application Support/entitlement-jail/logs/...`.
- `--log-stream stdout` + `--json-out` works: stream report on stdout, JSON response in file, `log_observer_path` populated.
- Issue: stream-mode observer reports can mark `observed_deny=true` even when only the filter prelude is present; `deny_lines` include the filter line; `log_rc=15` even when a report is written.

## Log capture path-class revalidation
- Command: `EJ_LOG_MODE=path_class PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario net_client`
- Result: `log_capture_status=requested_written` with container tmp paths; log files copied into `out/ej/logs` (`log_copy_error=None`).
- Issue: stream/observer reports still treat the filter prelude as a deny line (false positive), even when no Sandbox deny line is present.

## EntitlementJail update re-check (observer/stream)
- Command: `entitlement-jail run-xpc --log-stream <repo-log> --observe --observer-duration 2 --observer-format jsonl --observer-output auto --profile minimal capabilities_snapshot`
- Result: stream report `log_rc=0`, `observed_deny=false`, no filter prelude line; observer path ends with `.jsonl`.
- Command: `entitlement-jail run-xpc --log-stream <repo-log> --observe --observer-duration 2 --observer-format jsonl --observer-output auto --profile minimal net_op --op tcp_connect --host 127.0.0.1 --port 9`
- Result: stream report captures deny line (`observed_deny=true`), but embedded observer report shows `observed_deny=false` with empty `deny_lines`.

## Matrix group metadata re-check
- Command: `PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario matrix_groups --ack-risk fully_injectable`
- Result: `run-matrix.json` under each group still reports `group_id=jit` and the same profile set (`minimal`, `jit_map_jit`, `jit_rwx_legacy`) for baseline/debug/inject/jit groups.

## probe_families + bookmark_roundtrip re-check
- Commands: `PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario probe_families` and `PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario bookmark_roundtrip`
- Result: no `log_capture_status=requested_failed` or `log: Cannot run while sandboxed` errors; log capture succeeds for these scenarios.
- Result: fs_xattr set/get/list now return `normalized_outcome=ok` and `fs_op create` reports a concrete `file_path` under the container tmp dir.

## wait-path-class + wait-name re-check
- Command: `PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario wait_path_class`
- Result: wait-ready line emitted with `mode=fifo` and a concrete wait path under the service tmp dir; run exits 0.

## Deny evidence coverage gap re-checks
- Downloads scenario: `deny_evidence=not_found` for `fs_listdir` under both minimal and downloads_rw; no log deny lines observed.
- probe_families filesystem probes: `deny_evidence=not_found` for `fs_xattr` and `fs_coordinated_op`; no log deny lines observed.
- bookmark_roundtrip: minimal `roundtrip_stat` reports `deny_evidence=captured`; bookmarks_app_scope `roundtrip_stat` still reports `not_found`.

## Observer/stream alignment re-check
- Commands: re-ran `net_client`, `bookmarks`, `bookmark_roundtrip`, `probe_families`.
- Result: no mismatches between `deny_evidence` and `log_capture_observed_deny`/`log_observer_observed_deny`; embedded observer reports align with stream logs.
- Observation: deny lines now include both the sandboxd line and a `MetaData: {...}` line for bookmark-related probes.

## Log capture mode re-checks
- Command: `PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario run_matrix_out`
- Result: `data.output_dir` matches `--out`, report parsed, outputs copied; no path/matrix errors.
- Command: `entitlement-jail run-xpc --log-stream auto --observe --observer-duration 2 --observer-format jsonl --observer-output auto --profile minimal capabilities_snapshot`
- Result: `log_capture_path` and `log_observer_path` use app-managed log paths; stream report is JSON, observer report is JSONL (`.jsonl`); both files exist.

## wait_attach re-check
- Command: `PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario wait_attach`
- Result: `log_capture_status=requested_written` and `log_observer_status=requested_written` across wait/attach runs; no deny evidence expected or observed.

## run-matrix group metadata re-check (post-update)
- Commands: `entitlement-jail run-matrix --group baseline|debug|inject|jit capabilities_snapshot` (inject/jit with `--ack-risk fully_injectable`)
- Result: `data.group_id` now matches the requested group and profile lists differ per group (baseline: minimal; debug: minimal+debuggable; inject: minimal+plugin_host_relaxed+dyld_env_enabled+fully_injectable; jit: minimal+jit_map_jit+jit_rwx_legacy).

## downloads listdir deny evidence re-check
- Command: `entitlement-jail run-xpc --profile minimal --log-stream auto --observe --observer-duration 2 --observer-format jsonl --observer-output auto fs_op --op listdir --path-class downloads`
- Result: `normalized_outcome=permission_error` with `errno=1`, but `deny_evidence=not_found` and no deny lines in stream/observer reports.
