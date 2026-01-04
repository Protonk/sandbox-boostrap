# PolicyWitness keepalive + attach demo

Baseline: `world_id sonoma-14.4.1-23E224-arm64-dyld-a3a840f9`.

## Purpose

Demonstrate that the keepalive service can hold a target open and that Frida
can attach reliably to PolicyWitness attachable variants. This is a host-bound
demonstration of tooling behavior, not a sandbox semantics claim.

## Prereqs

1) Use the repo venv for Python:

```sh
./.venv/bin/python -m book.api.witness.frida.preflight
```

2) Build helpers:

```sh
book/api/witness/native/hold_open/build.sh
book/api/witness/native/sb_api_validator/build.sh
book/api/frida/native/attach_helper/build.sh
```

3) Sign the attach helper (DER entitlements required):

```sh
codesign --force --sign "<identity>" \
  --entitlements book/api/frida/native/attach_helper/entitlements.plist \
  --generate-entitlement-der \
  book/api/frida/native/attach_helper/frida_attach_helper
```

4) Confirm entitlements on the helper:

```sh
codesign -d --entitlements :- book/api/frida/native/attach_helper/frida_attach_helper
```

## Output location

All demo runs should write under:

```
book/evidence/demonstration/witness/out/
```

Use repo-relative paths only. If you automate, use `book.api.path_utils` to
normalize paths.

## Demonstration runs

### A) Keepalive + hold_open + Frida attach

Stage: `operation`, Lane: `oracle` (keepalive/Frida only).

```sh
./.venv/bin/python -m book.api.witness.keepalive hook-frida \
  --spawn-hold-open \
  --script book/api/frida/hooks/smoke.js \
  --out-dir book/evidence/demonstration/witness/out/hold-open \
  --helper \
  --stage operation \
  --lane oracle \
  > book/evidence/demonstration/witness/out/hold-open/hook.json
```

Expected artifacts:
- `book/evidence/demonstration/witness/out/hold-open/events.jsonl`
- `book/evidence/demonstration/witness/out/hold-open/meta.json`
- `book/evidence/demonstration/witness/out/hold-open/hook.json` (stdout JSON)
- Keepalive events path is included in `hook.json`.

Success criteria:
- `hook.status == "ready"` in `hook.json`
- `events.jsonl` is non-empty

### B) PolicyWitness attach-first (injectable variant)

Stage: `operation`, Lane: `oracle` for keepalive + Frida metadata.
PolicyWitness probe results are stage `operation`, lane `scenario` (best-effort;
the CLI does not label lane explicitly).

```sh
./.venv/bin/python -m book.api.witness.frida \
  --profile-id minimal@injectable \
  --probe-id capabilities_snapshot \
  --script book/api/frida/hooks/smoke.js \
  --out-dir book/evidence/demonstration/witness/out \
  --keepalive \
  --frida-helper
```

Expected artifacts (under the newest run dir):
- `book/evidence/demonstration/witness/out/<run_id>/manifest.json`
- `book/evidence/demonstration/witness/out/<run_id>/witness/run_probe.json`
- `book/evidence/demonstration/witness/out/<run_id>/frida/events.jsonl`
- `book/evidence/demonstration/witness/out/<run_id>/frida/meta.json`

Success criteria:
- `manifest.json` has `frida.attach_error: null`
- `frida.meta.json` includes `pid_matches_service_pid: true`

### C) Negative control (base variant)

Stage: `operation`, Lane: `oracle` for keepalive + Frida metadata.

```sh
./.venv/bin/python -m book.api.witness.frida \
  --profile-id minimal \
  --probe-id capabilities_snapshot \
  --script book/api/frida/hooks/smoke.js \
  --out-dir book/evidence/demonstration/witness/out \
  --keepalive \
  --frida-helper
```

Expected outcome:
- `manifest.json` reports a non-empty `frida.attach_error` or keepalive error,
  consistent with the base variant lacking `get-task-allow`.

### D) Oracle lane cross-check (`sandbox_check`)

Stage: `operation`, Lane: `oracle`.

Use the PID from the **injectable** run (`manifest.json`, `frida.attach_meta.pid`)
and run `sb_api_validator`:

```sh
./.venv/bin/python - <<'PY'
import json
from pathlib import Path

manifest = json.loads(Path("book/evidence/demonstration/witness/out/<run_id>/manifest.json").read_text())
pid = manifest["frida"]["attach_meta"]["pid"]
print(pid)
PY

book/api/witness/native/sb_api_validator/sb_api_validator --json \
  <pid> file-read* PATH /etc/hosts
```

Expected:
- `kind == "sb_api_validator_result"`
- `operation == "file-read*"` and `filter_type == "PATH"`

### E) Repeatability pass

Run step **B** twice and compare:
- `frida.attach_error` should remain `null`.
- `pid_matches_service_pid` should remain `true`.
- `run_id`, `target_id`, and `hook_id` may differ (expected).

## Common failure modes

- **Invalid entitlements blob**: re-sign helper with `--generate-entitlement-der`.
- **PermissionDeniedError**: target likely lacks `get-task-allow` (use `@injectable`).
- **taskgated denies**: attach is blocked by system policy; verify the helper is
  correctly signed and the target is debuggable.

## Stretch goal (not achieved yet)

One-command demo that:
- builds + signs the helper automatically,
- runs all scenarios in sequence,
- emits a single, stable output bundle without manual intervention.

Current blockers: local codesign identity workflow and attach entitlement policy.
