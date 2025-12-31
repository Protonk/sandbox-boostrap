# policywitness (API)

This package wraps PolicyWitness.app for the Sonoma baseline. It provides a small Python surface for driving:

- `policy-witness xpc run` (one-shot probes)
- `policy-witness xpc session` (attach-first sessions)
- `sandbox-log-observer` (deny evidence outside the sandbox boundary)

This API expects PolicyWitness.app at `book/tools/witness/PolicyWitness.app`.

## Entry points
- `book.api.policywitness.cli.run_xpc` (single probe via `xpc run`)
- `book.api.policywitness.protocol.WaitSpec` (typed wait spec for `xpc session --wait`)
- `book.api.policywitness.session.open_session` (start + return a ready session)
- `book.api.policywitness.session.XpcSession` (multi-probe `xpc session` control plane; event iteration + observer helpers)
- `book.api.policywitness.frida` (PolicyWitness xpc session + Frida attach harness)
- `book.api.policywitness.cli.list_profiles` / `list_services` (profile/service inventory)
- `book.api.policywitness.cli.show_profile` / `describe_service` / `health_check` (profile + service reports)
- `book.api.policywitness.cli.run_matrix_group` (matrix group run via `--out`)
- `book.api.policywitness.cli.run_matrix` (matrix run for a specific probe)
- `book.api.policywitness.cli.bundle_evidence` (evidence bundle via `--out`)
- `book.api.policywitness.cli.verify_evidence` / `inspect_macho` (evidence inspection)
- `book.api.policywitness.cli.load_evidence_manifest` / `load_evidence_profiles` / `load_evidence_symbols` (load bundled evidence JSON)
- `book.api.policywitness.cli.quarantine_lab` (resolve bundle id from profile, run quarantine-lab)

## Frida harness
Attach-first Frida runs for PolicyWitness live in `book/api/policywitness/frida.py`.

Example:
```sh
python -m book.api.policywitness.frida \
  --profile-id minimal@injectable \
  --probe-id probe_catalog \
  --script book/api/frida/hooks/smoke.js
```

Notes:
- PolicyWitness XPC sessions may require elevated permissions outside the harness sandbox.

## Observer defaults
Observer capture is enabled by default when callers provide a `log_path`.

Environment toggles:
- `PW_LOG_OBSERVER=external|disabled` (default: external)
- `PW_LOG_LAST=10s` (fallback `--last` window)
- `PW_LOG_PAD_S=2.0` (padding for `--start/--end` windows)

# Contract

The stable CLI and JSON shapes are documented below and guarded by fixtures in `book/tools/witness/fixtures/contract/`.

# PolicyWitness Contract

This document captures the stable PolicyWitness.app interface that the tooling depends on. It is not a claim about sandbox semantics; it is a tool contract anchored by local fixtures on the Sonoma baseline.

## Purpose
- Provide a stable, host-bound contract for PolicyWitness CLI access used by experiments.
- Keep the contract enforceable via fixtures and tests.
- Avoid over-claiming: these are tool interface observations on the Sonoma baseline.

## Scope
We depend on:
- `policy-witness xpc run` for one-shot probe execution.
- `policy-witness xpc session` for attach-first, multi-probe sessions.
- `sandbox-log-observer` for deny evidence (observer-only, outside the sandbox).

We do not rely on integrated `log stream` capture (removed in v2); deny evidence is observer-only.

## CLI contract (observed)
The CLI help text must include:
- `xpc run` with `--profile`/`--service`, `--variant` (or `<id[@variant]>`), `--plan-id`, `--row-id`, `--correlation-id`.
- `xpc run` with `--capture-sandbox-logs` (optional log capture inside PolicyWitness).
- `xpc session` with `--profile`/`--service`, `--variant` (or `<id[@variant]>`), `--plan-id`, `--correlation-id`, `--wait`, `--wait-timeout-ms`, `--wait-interval-ms`, `--xpc-timeout-ms`.
- `sandbox-log-observer` with `--pid`, `--process-name`, `--start`, `--end`, `--last`, `--duration`, `--follow`, `--predicate`.
- `sandbox-log-observer` with `--format`, `--output`.
- `sandbox-log-observer` with `--plan-id`, `--row-id`, `--correlation-id`.

See fixtures:
- `book/tools/witness/fixtures/contract/policy-witness.help.txt`
- `book/tools/witness/fixtures/contract/sandbox-log-observer.help.txt`

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
- `book/tools/witness/fixtures/contract/observer.sample.json`

## Guardrails
Tests validate the help text and observer JSON shape using these fixtures. See:
- `book/integration/tests/tools/test_policywitness_contract.py`
