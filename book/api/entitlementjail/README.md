# entitlementjail (API)

This package wraps EntitlementJail.app for the Sonoma baseline. It provides a small Python surface for driving:

- `entitlement-jail xpc run` (one-shot probes)
- `entitlement-jail xpc session` (attach-first sessions)
- `sandbox-log-observer` (deny evidence outside the sandbox boundary)

This API expects EntitlementJail.app at `book/tools/entitlement/EntitlementJail.app`.

## Entry points
- `book.api.entitlementjail.cli.run_xpc` (single probe via `xpc run`)
- `book.api.entitlementjail.wait.run_wait_xpc` (single probe via `xpc session` + wait barrier)
- `book.api.entitlementjail.wait.run_probe_wait` (probe-internal waits like `fs_op_wait`)
- `book.api.entitlementjail.session.XpcSession` (multi-probe `xpc session` control plane)
- `book.api.entitlementjail.cli.run_matrix_group` (matrix group run via `--out`)
- `book.api.entitlementjail.cli.bundle_evidence` (evidence bundle via `--out`)

## Observer defaults
Observer capture is enabled by default when callers provide a `log_path`.

Environment toggles:
- `EJ_LOG_OBSERVER=external|disabled` (default: external; `embedded` is treated as `external` for compatibility)
- `EJ_LOG_LAST=10s` (fallback `--last` window)
- `EJ_LOG_PAD_S=2.0` (padding for `--start/--end` windows)

# Contract

The stable CLI and JSON shapes are documented below and guarded by fixtures in `book/tools/entitlement/fixtures/contract/`.

# EntitlementJail Contract

This document captures the stable EntitlementJail.app interface that the tooling depends on. It is not a claim about sandbox semantics; it is a tool contract anchored by local fixtures on the Sonoma baseline.

## Purpose
- Provide a stable, host-bound contract for EntitlementJail CLI access used by experiments.
- Keep the contract enforceable via fixtures and tests.
- Avoid over-claiming: these are tool interface observations on the Sonoma baseline.

## Scope
We depend on:
- `entitlement-jail xpc run` for one-shot probes.
- `entitlement-jail xpc session` for attach-first workflows.
- `sandbox-log-observer` for deny evidence (observer-only, outside the sandbox).

We do not rely on integrated `log stream` capture (removed in v2); deny evidence is observer-only.

## CLI contract (observed)
The CLI help text must include:
- `xpc run` with `--profile`/`--service`, `--ack-risk`, `--plan-id`, `--row-id`, `--correlation-id`.
- `xpc session` with `--profile`/`--service`, `--ack-risk`, `--plan-id`, `--correlation-id`, `--wait`, `--wait-timeout-ms`, `--wait-interval-ms`, `--xpc-timeout-ms`.
- `sandbox-log-observer` with `--pid`, `--process-name`, `--start`, `--end`, `--last`, `--duration`, `--follow`.
- `sandbox-log-observer` with `--format`, `--output`.
- `sandbox-log-observer` with `--plan-id`, `--row-id`, `--correlation-id`.

See fixtures:
- `book/tools/entitlement/fixtures/contract/entitlement-jail.help.txt`
- `book/tools/entitlement/fixtures/contract/sandbox-log-observer.help.txt`

## JSON contract (observer-only)
We depend on these fields:

Probe response (JSON stdout):
- `schema_version` (int)
- `kind: "probe_response"`
- `result.normalized_outcome` (string)
- `data.details.pid` (or `service_pid`/`probe_pid`) and `data.details.process_name` (strings; best-effort)
- `data.details.correlation_id` (string)

`sandbox-log-observer` response (JSON stdout):
- `kind: "sandbox_log_observer_report"`
- `data.pid` (int) and `data.process_name` (string)
- `data.observed_deny` (bool)
- `data.plan_id`, `data.row_id`, `data.correlation_id` (strings)
- `data.predicate` (string)

See fixtures:
- `book/tools/entitlement/fixtures/contract/observer.sample.json`

## Guardrails
Tests validate the help text and observer JSON shape using these fixtures. See:
- `book/tests/test_entitlementjail_contract.py`
