# Wait/Attach Workflow (EntitlementJail 1.x)

## Purpose
This note records the EntitlementJail 1.x wait and attach workflows as exercised in `book/experiments/entitlement-diff`. It is scoped to the Sonoma 14.4.1 host baseline and treats runtime claims as partial evidence tied to the outputs listed below.

## Baseline and evidence status
- world_id: sonoma-14.4.1-23E224-arm64-dyld-2c0602c5
- Evidence tier: partial runtime evidence; log capture is requested but fails with `write_failed` (operation not permitted) when writing under the service tmp dir, so deny evidence is not captured.

## Run-xpc wait and attach (partial)
`run-xpc` emits a wait-ready line to stderr when a wait is active. The runner in this experiment reads that line, extracts `mode` and `wait_path`, then triggers the probe by writing to the FIFO or creating the wait-exists file.

Observed behavior (partial, host-specific):
- `--attach <seconds>` uses FIFO mode and emits a wait-ready line. See `book/experiments/entitlement-diff/out/ej/wait_attach.json`.
- `--wait-fifo <path>` blocks until a writer connects. See `book/experiments/entitlement-diff/out/ej/wait_attach.json`.
- `--wait-exists <path>` polls until a file exists. See `book/experiments/entitlement-diff/out/ej/wait_attach.json`.
- `--hold-open <seconds>` extends process lifetime after the probe returns; a 3 second hold produced a run duration of about 3.1 seconds. See `book/experiments/entitlement-diff/out/ej/wait_hold_open.json`.

## Wait timeout behavior (partial)
`--wait-timeout-ms` expects literal integer milliseconds. In the timeout matrix, trigger delays shorter than the timeout returned exit_code 0, while delays longer than the timeout returned exit_code 1. See `book/experiments/entitlement-diff/out/ej/wait_timeout_matrix.json`.

## Wait-create (FIFO auto-create)
When using `--wait-fifo`, `--wait-create` creates the FIFO under the service container without pre-creating it on the host. The FIFO remains present after the run in this host. See `book/experiments/entitlement-diff/out/ej/wait_create.json`.

## Wait-interval for exists waits
`--wait-interval-ms` is reflected in `data.details.wait_interval_ms` for `--wait-exists` waits. See `book/experiments/entitlement-diff/out/ej/wait_interval.json`.

## Probe-level wait (fs_op_wait)
`fs_op_wait` embeds the wait inside the probe rather than the CLI. In the latest rerun, `fs_op_wait` emits a wait-ready line for both FIFO and exists waits, and the runner triggers using the reported wait path. Both waits completed with exit_code 0. See `book/experiments/entitlement-diff/out/ej/wait_probe_wait.json`.

## Multi-trigger behavior (partial)
Triggering a FIFO twice results in a post-trigger error (`OSError: [Errno 6] Device not configured`), consistent with the FIFO reader being gone after the first trigger. `--wait-exists` tolerates repeated triggers. See `book/experiments/entitlement-diff/out/ej/wait_multi_trigger.json`.

## wait-path-class and wait-name
`--wait-path-class tmp --wait-name ej_wait_path_class` now works without supplying an explicit wait path. The CLI emits a wait-ready line that includes the FIFO path under the service container, and triggering the FIFO completes the probe with exit_code 0. See `book/experiments/entitlement-diff/out/ej/wait_path_class.json`.

## Attach default hold-open behavior
`--attach <seconds>` without an explicit `--hold-open` kept the process alive for about the attach duration on this host. Passing `--hold-open 0` returns promptly after the trigger. See `book/experiments/entitlement-diff/out/ej/attach_holdopen_default.json`.

## Repro commands
- `PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario wait_attach`
- `PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario wait_timeout_matrix`
- `PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario wait_create`
- `PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario wait_interval`
- `PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario wait_multi_trigger`
- `PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario wait_probe_wait`
- `PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario wait_hold_open`
- `PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario attach_holdopen_default`
- `PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario wait_path_class`
