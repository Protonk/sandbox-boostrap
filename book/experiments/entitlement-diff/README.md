# entitlement-diff (EntitlementJail tooling)

This experiment treats EntitlementJail.app as a stable tool API and uses it to generate host-bound evidence about entitlements and sandbox outcomes.

## Observer-first logging
- Deny evidence is captured by the external `sandbox-log-observer` helper (outside the sandbox boundary).
- In-sandbox log stream/show capture is legacy and not used for attribution in v2.

## Quick start
Run a known scenario:

```
PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario net_client
```

Run cross-profile network probes:

```
PYTHONPATH=. python book/experiments/entitlement-diff/run_entitlementjail.py --scenario net_op_groups
```

## Adding new probes (model pattern)
1) Add a scenario in `book/experiments/entitlement-diff/ej_scenarios.py`.
2) Use `run_xpc` (from `book/api/entitlementjail/cli.py`) or `XpcSession`/`open_session` for wait-barrier flows.
3) Always pass a `log_path`, `plan_id`, and `row_id` so the observer output is correlated.
4) Consume `observer` (PID-scoped) output as the deny evidence source.

## Contract and tests
The stable CLI and JSON shapes are documented and guarded:
- Contract doc: `book/api/entitlementjail/README.md` (Contract section)
- Fixtures: `book/tools/entitlement/fixtures/contract/`
- Tests: `book/tests/planes/tools/test_entitlementjail_contract.py`

## Environment toggles
Defaults are observer-first:
- `EJ_LOG_OBSERVER=external|disabled` (default: external)
- `EJ_LOG_LAST=10s` (fallback window)
- `EJ_LOG_PAD_S=2.0` (padding for `--start/--end` windows)
