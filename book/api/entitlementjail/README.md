# entitlementjail (API)

This package wraps EntitlementJail.app for the Sonoma baseline. It provides a small Python surface for driving:

- `entitlement-jail xpc run` (one-shot probes)
- `entitlement-jail xpc session` (attach-first sessions)
- `sandbox-log-observer` (deny evidence outside the sandbox boundary)

This API expects EntitlementJail.app at `book/tools/entitlement/EntitlementJail.app`.

## Entry points
- `book.api.entitlementjail.cli.run_xpc` (single probe via `xpc run`)
- `book.api.entitlementjail.protocol.WaitSpec` (typed wait spec for `xpc session --wait`)
- `book.api.entitlementjail.session.open_session` (start + return a ready session)
- `book.api.entitlementjail.session.XpcSession` (multi-probe `xpc session` control plane; event iteration + observer helpers)
- `book.api.entitlementjail.frida` (EntitlementJail xpc session + Frida attach harness)
- `book.api.entitlementjail.cli.list_profiles` / `list_services` (profile/service inventory)
- `book.api.entitlementjail.cli.show_profile` / `describe_service` / `health_check` (profile + service reports)
- `book.api.entitlementjail.cli.run_matrix_group` (matrix group run via `--out`)
- `book.api.entitlementjail.cli.run_matrix` (matrix run for a specific probe)
- `book.api.entitlementjail.cli.bundle_evidence` (evidence bundle via `--out`)
- `book.api.entitlementjail.cli.verify_evidence` / `inspect_macho` (evidence inspection)
- `book.api.entitlementjail.cli.load_evidence_manifest` / `load_evidence_profiles` / `load_evidence_symbols` (load bundled evidence JSON)
- `book.api.entitlementjail.cli.quarantine_lab` (resolve bundle id from profile, run quarantine-lab)

## Frida harness
Attach-first Frida runs for EntitlementJail live in `book/api/entitlementjail/frida.py`.

Example:
```sh
python -m book.api.entitlementjail.frida \
  --profile-id minimal@injectable \
  --probe-id probe_catalog \
  --script book/api/frida/hooks/smoke.js
```

Notes:
- EntitlementJail XPC sessions may require elevated permissions outside the harness sandbox.

## Observer defaults
Observer capture is enabled by default when callers provide a `log_path`.

Environment toggles:
- `EJ_LOG_OBSERVER=external|disabled` (default: external)
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
- `entitlement-jail xpc run` for one-shot probe execution.
- `entitlement-jail xpc session` for attach-first, multi-probe sessions.
- `sandbox-log-observer` for deny evidence (observer-only, outside the sandbox).

We do not rely on integrated `log stream` capture (removed in v2); deny evidence is observer-only.

## CLI contract (observed)
The CLI help text must include:
- `xpc run` with `--profile`/`--service`, `--variant` (or `<id[@variant]>`), `--plan-id`, `--row-id`, `--correlation-id`.
- `xpc session` with `--profile`/`--service`, `--variant` (or `<id[@variant]>`), `--plan-id`, `--correlation-id`, `--wait`, `--wait-timeout-ms`, `--wait-interval-ms`, `--xpc-timeout-ms`.
- `sandbox-log-observer` with `--pid`, `--process-name`, `--start`, `--end`, `--last`, `--duration`, `--follow`, `--predicate`.
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
