# Entitlement tools

This directory holds EntitlementJail.app and its adjacent fixtures. It is the home for App Sandbox + entitlement tooling on the Sonoma baseline.

## EntitlementJail.app
User guide: `EntitlementJail.md`

EntitlementJail is a macOS research/teaching tool for exploring App Sandbox and entitlements using a host-side CLI plus sandboxed XPC services. The guide documents workflows, logging/observer behavior, and output formats.

## Fixtures
Fixtures live under `fixtures/` and capture stable CLI/JSON shapes the tooling expects.

### Contract fixtures
- `fixtures/contract/entitlement-jail.help.txt`
- `fixtures/contract/sandbox-log-observer.help.txt`
- `fixtures/contract/observer.sample.json`

### Refresh (manual)
- `EntitlementJail.app/Contents/MacOS/entitlement-jail --help > fixtures/contract/entitlement-jail.help.txt 2>&1` (prints help to stderr)
- `EntitlementJail.app/Contents/MacOS/sandbox-log-observer --help > fixtures/contract/sandbox-log-observer.help.txt 2>&1` (prints help to stderr)
- Run a probe to get a service PID/process name, then capture observer output (outside the sandbox):
  - `entitlement-jail xpc run --profile minimal --plan-id contract --row-id observer.sample --correlation-id "$(uuidgen)" capabilities_snapshot > /tmp/ej_probe.json`
  - `PID=$(plutil -extract data.details.pid raw -o - /tmp/ej_probe.json)`
  - `NAME=$(plutil -extract data.details.process_name raw -o - /tmp/ej_probe.json)`
  - `CORR=$(plutil -extract data.correlation_id raw -o - /tmp/ej_probe.json)`
  - `sandbox-log-observer --pid "$PID" --process-name "$NAME" --last 10s --plan-id contract --row-id observer.sample --correlation-id "$CORR" --format json > fixtures/contract/observer.sample.json`
