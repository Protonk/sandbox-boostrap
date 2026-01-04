# PolicyWitness tools

This directory holds PolicyWitness.app and its adjacent fixtures. It is the home for App Sandbox + entitlement tooling on the Sonoma baseline.

## PolicyWitness.app
User guide: `PolicyWitness.md`

PolicyWitness is a macOS research/teaching tool for exploring App Sandbox and entitlements using a host-side CLI plus sandboxed XPC services. The guide documents workflows, logging/observer behavior, and output formats.

## Fixtures
Fixtures live under `fixtures/` and capture stable CLI/JSON shapes the tooling expects.

### Contract fixtures
- `fixtures/contract/policy-witness.help.txt`
- `fixtures/contract/sandbox-log-observer.help.txt`
- `fixtures/contract/signpost-log-observer.help.txt`
- `fixtures/contract/xpc-quarantine-client.help.txt`
- `fixtures/contract/observer.sample.json`

### Refresh (manual)
- `PolicyWitness.app/Contents/MacOS/policy-witness --help > fixtures/contract/policy-witness.help.txt 2>&1` (prints help to stderr)
- `PolicyWitness.app/Contents/MacOS/sandbox-log-observer --help > fixtures/contract/sandbox-log-observer.help.txt 2>&1` (prints help to stderr)
- Run a probe to get a service PID/process name, then capture observer output (outside the sandbox):
  - `policy-witness xpc run --profile minimal --plan-id contract --row-id observer.sample --correlation-id "$(uuidgen)" capabilities_snapshot > /tmp/pw_probe.json`
  - `PID=$(plutil -extract data.details.service_pid raw -o - /tmp/pw_probe.json)`
  - `NAME=$(plutil -extract data.details.process_name raw -o - /tmp/pw_probe.json)`
  - `CORR=$(plutil -extract data.details.correlation_id raw -o - /tmp/pw_probe.json)`
  - `sandbox-log-observer --pid "$PID" --process-name "$NAME" --last 10s --plan-id contract --row-id observer.sample --correlation-id "$CORR" --format json > fixtures/contract/observer.sample.json`
