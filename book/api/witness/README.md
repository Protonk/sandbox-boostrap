# witness (API)

Host-bound Python API for PolicyWitness.app on the Sonoma baseline. This package wraps the PolicyWitness CLI and observer and provides lifecycle snapshots, baseline comparisons, and enforcement detail helpers.

PolicyWitness app bundle: `book/tools/witness/PolicyWitness.app`

## Entry points
- `book.api.witness.client.run_probe` / `run_probe_request` (one-shot probes via `xpc run`)
- `book.api.witness.session.open_session` / `XpcSession` (`xpc session` control plane)
- `book.api.witness.keepalive.open_keepalive` / `spawn_hold_open` / `open_policywitness_session` (keepalive connectors)
- `book.api.witness.sb_api_validator.run_sb_api_validator` (sandbox_check oracle lane)
- `book.api.witness.lifecycle.snapshot_from_probe` / `snapshot_from_session` (on-demand lifecycle snapshots)
- `book.api.witness.enforcement.enforcement_detail` (minute enforcement detail from probe + observer)
- `book.api.witness.compare.compare_action` (entitlements/SBPL/none baseline comparison)
- `book.api.witness.outputs.OutputSpec` (output layout control)
- `book.api.witness.frida` (PolicyWitness attach-first Frida harness)
- `book.api.witness.client.list_profiles` / `list_services` / `show_profile` / `describe_service`

## Health check (recommended first step)
```py
from book.api.witness import client

health = client.health_check()
print(health["stdout_json"]["data"]["ok"])
```

## Keepalive connectors
Use these to get a stable PID without ad-hoc glue. Modes:

- `policywitness_session`: keep a PolicyWitness XPC service alive (supports `keepalive` + wait barrier).
- `spawn_hold_open`: start a minimal helper that blocks until signaled.
- `pid_lease`: attach-only handle for an existing PID (no keepalive, just liveness checks).

PolicyWitness session example:

```py
from book.api.witness import keepalive

with keepalive.open_policywitness_session(
    profile_id="minimal",
    plan_id="witness:keepalive",
    wait_spec="fifo:auto",
    heartbeat_s=5.0,
) as handle:
    print(handle.record.pid)
    handle.trigger_wait()
```

Spawn hold_open example (build with `book/api/witness/native/hold_open/build.sh` first):

```py
from book.api.witness import keepalive

with keepalive.spawn_hold_open(wait_spec="fifo:auto") as handle:
    print(handle.record.pid)
    handle.trigger_wait()
```

To run hold_open under another wrapper (for example SBPL apply), pass a prefix:

```py
from book.api.witness import keepalive

prefix = ["book/tools/sbpl/wrapper/wrapper", "--sbpl", "path/to/profile.sb", "--"]
handle = keepalive.spawn_hold_open(command_prefix=prefix)
```

## CLI to API mapping (high level)
- `policy-witness list-profiles` -> `client.list_profiles`
- `policy-witness list-services` -> `client.list_services`
- `policy-witness show-profile <id>` -> `client.show_profile`
- `policy-witness describe-service <id@variant>` -> `client.describe_service`
- `policy-witness xpc run --profile ...` -> `client.run_probe`
- `policy-witness xpc session ...` -> `session.open_session`
- `policy-witness run-matrix ...` -> `client.run_matrix`
- `policy-witness bundle-evidence` -> `client.bundle_evidence`
- `policy-witness verify-evidence` -> `client.verify_evidence`
- `policy-witness inspect-macho ...` -> `client.inspect_macho`
- `sandbox-log-observer` -> `observer.run_sandbox_log_observer`
- `policy-witness quarantine-lab ...` -> `client.quarantine_lab` (see note below)
- CLI-only: `run-system`, `run-embedded`, `xpc-quarantine-client`

## Output layout (OutputSpec)
`OutputSpec(out_dir=Path(...))` writes:
- `logs/<plan_id>.<row_id>.<probe_id>.json` (probe JSON)
- `records/<plan_id>.<row_id>.<probe_id>.record.json` (ProbeResult envelope)
- `logs/observer/<plan_id>.<row_id>.<probe_id>.json.observer.json` (sandbox-log-observer report)

Bundle mode (optional):
- Set `bundle_root=Path(...)` to write into `bundle_root/<run_id>/...` and emit
  `artifact_index.json` for the run-scoped directory.
- Set `bundle_run_id` to pin the run directory name (default is a generated UUID).

Disable the external observer when you already used `--capture-sandbox-logs`:
```sh
WITNESS_OBSERVER_MODE=disabled
```

## Quick probe example
```py
from pathlib import Path

from book.api.witness import client, outputs

result = client.run_probe(
    profile_id="minimal",
    probe_id="capabilities_snapshot",
    probe_args=[],
    plan_id="witness:sample",
    row_id="capabilities_snapshot",
    output=outputs.OutputSpec(
        bundle_root=Path("book/api/witness/out"),
        bundle_run_id="witness-sample",
    ),
)
print(result.stdout_json)
```

## Service-id probe example
```py
from book.api.witness import client

profiles = client.show_profile("minimal")
variants = profiles["stdout_json"]["data"]["profile"]["variants"]
service_id = variants[0]["bundle_id"]

result = client.run_probe(
    service_id=service_id,
    probe_id="capabilities_snapshot",
    probe_args=[],
    plan_id="witness:service-id",
)
print(result.stdout_json["data"]["service_bundle_id"])
```

## XPC session wait flow (attach-first)
```py
from book.api.witness import session

with session.open_session(profile_id="minimal", plan_id="witness:session", wait_spec="fifo:auto") as sess:
    pre = sess.run_probe(probe_id="capabilities_snapshot", argv=[])
    # Expect normalized_outcome "session_not_triggered" until trigger.
    print(pre["result"]["normalized_outcome"])
    sess.trigger_wait()
    sess.wait_for_trigger_received(timeout_s=5.0)
    post = sess.run_probe(probe_id="capabilities_snapshot", argv=[])
    print(post["result"]["normalized_outcome"])
```

## Lifecycle + enforcement detail
```py
from book.api.witness import enforcement, lifecycle

snapshot = lifecycle.snapshot_from_probe(result.stdout_json, profile_id="minimal")
print(snapshot.to_json())

detail = enforcement.enforcement_detail_from_probe_result(result)
print(detail.to_json())
```

## Baseline comparison (entitlements/SBPL/none)
```py
from pathlib import Path

from book.api.witness import compare, models

action = models.ActionSpec(
    action_id="fs_read_hosts",
    entitlements=models.EntitlementAction(
        profile_id="minimal",
        probe_id="fs_op",
        probe_args=["--op", "open_read", "--path", "/etc/hosts"],
    ),
    sbpl=models.SbplAction(
        command=models.CommandSpec(argv=["/bin/cat", "/etc/hosts"]),
        sbpl_path=Path("book/evidence/experiments/runtime-final-final/suites/runtime-checks/sb/profile.sb"),
    ),
    none=models.CommandSpec(argv=["/bin/cat", "/etc/hosts"]),
)
report = compare.compare_action(action)
print(report.to_json())
```

## Sandbox_check oracle lane
Use `sb_api_validator` to query `sandbox_check()` against a target PID (oracle only):

```py
from book.api.witness import sb_api_validator

result = sb_api_validator.run_sb_api_validator(
    pid=1234,
    operation="file-read*",
    filter_type="path",
    filter_value="/etc/hosts",
)
print(result["stdout_json"])
```

Build the helper first if needed:

```sh
book/api/witness/native/sb_api_validator/build.sh
```

Attach it to tri-run by adding `sandbox_check` to `ActionSpec`:

```py
from book.api.witness import compare, models

action = models.ActionSpec(
    action_id="fs_read_hosts",
    entitlements=models.EntitlementAction(
        profile_id="minimal",
        probe_id="fs_op",
        probe_args=["--op", "open_read", "--path", "/etc/hosts"],
    ),
    sbpl=models.SbplAction(
        command=models.CommandSpec(argv=["/bin/cat", "/etc/hosts"]),
        sbpl_path=Path("book/evidence/experiments/runtime-final-final/suites/runtime-checks/sb/profile.sb"),
    ),
    none=models.CommandSpec(argv=["/bin/cat", "/etc/hosts"]),
    sandbox_check=models.SandboxCheckSpec(
        operation="file-read*",
        filter_type="path",
        filter_value="/etc/hosts",
    ),
)
report = compare.compare_action(action)
print(report.to_json()["results"]["sandbox_check"])
```

## Common outcomes (not automatic denials)
- `connection_refused`: host-side TCP connect failed; not a sandbox denial.
- `permission_error`: permission-shaped failure; use observer to attribute.
- `not_found`: harness file was removed or path is invalid.
- `consume_ok`: sandbox extension token accepted; verify access separately.
- `invalid_token`: try `--token-format prefix` when releasing/consuming.

## Observer defaults
Observer capture is enabled by default when outputs are configured and the probe returns JSON.

Environment toggles:
- `WITNESS_OBSERVER_MODE=external|disabled` (default: external)
- `WITNESS_OBSERVER_LAST=10s` (fallback `--last` window)
- `WITNESS_OBSERVER_PAD_S=2.0` (padding for `--start/--end` windows)

## Quarantine Lab
Use `variant` when you want the injectable service, or pass `bundle_id` directly:

```py
from book.api.witness import client

result = client.quarantine_lab(
    profile_id="quarantine_default",
    payload_class="text",
    payload_args=["--dir", "tmp"],
    variant="base",
)
print(result["run"]["stdout_json"]["result"])
```

## Path normalization
Probe payloads often contain absolute container paths. Normalize any recorded paths with `book.api.path_utils`
before committing artifacts.

# Contract

The stable CLI and JSON shapes are documented below and guarded by fixtures in `book/tools/witness/fixtures/contract/`.

## PolicyWitness contract

This document captures the stable PolicyWitness.app interface that the tooling depends on. It is not a claim about sandbox semantics; it is a tool contract anchored by local fixtures on the Sonoma baseline.

### Scope
We depend on:
- `policy-witness xpc run` for one-shot probe execution.
- `policy-witness xpc session` for attach-first, multi-probe sessions.
- `sandbox-log-observer` for deny evidence (observer-only, outside the sandbox).

We do not rely on integrated `log stream` capture (removed in v2); deny evidence is observer-only.

### CLI contract (observed)
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

### JSON contract (observer-only)
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

### Guardrails
Tests validate the help text and observer JSON shape using these fixtures. See:
- `book/integration/tests/tools/test_witness_contract.py`
