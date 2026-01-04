# Attach Guide (PolicyWitness + Keepalive + Frida)

Scope: host baseline `sonoma-14.4.1-23E224-arm64-dyld-a3a840f9`.

This guide explains how to attach Frida to PolicyWitness services using the keepalive daemon and the signed attach helper. It highlights the common failure modes and how to confirm the target is attachable.

## Quick mental model
- **Debuggee**: the PolicyWitness XPC service you want to attach to.
- **Debugger**: the process that calls `task_for_pid` (Frida attach). In this flow, that is the signed attach helper.
- **Keepalive**: keeps the target alive and exposes a control socket for hooks.

Attaching only works when the **debuggee** has `com.apple.security.get-task-allow=true` and is not blocked by hardened runtime policy. The injectable variants provide this entitlement; the base variants usually do not.

## Prereqs
1) Use the venv interpreter for all Python commands:

```sh
./.venv/bin/python -m book.api.witness.frida.preflight
```

2) Build the helper:

```sh
book/api/frida/native/attach_helper/build.sh
```

3) Sign the helper (DER entitlements required):

```sh
codesign --force --sign "Developer ID Application: Adam Hyland (42D369QV8E)" \
  --entitlements book/api/frida/native/attach_helper/entitlements.plist \
  --generate-entitlement-der \
  book/api/frida/native/attach_helper/frida_attach_helper
```

4) Confirm entitlements:

```sh
codesign --display --entitlements - --xml book/api/frida/native/attach_helper/frida_attach_helper
```

## Choose an attachable target
PolicyWitness profiles have variants; use the injectable variant for attach.

- Base (not attachable): `minimal`
- Injectable (attachable): `minimal@injectable`

Confirm the **running** service has `get-task-allow`:

```sh
# Start a session to get the service pid.
./.venv/bin/python - <<'PY'
from book.api.witness.xpc.session import XpcSession
s = XpcSession(profile_id="minimal@injectable", plan_id="diagnostic:attach")
s.start(ready_timeout_s=15)
print(s.pid())
s.close()
PY

# Check entitlements on the running process.
codesign -d --entitlements :- <pid>
```

Expected output includes `com.apple.security.get-task-allow` for the injectable variant.

## Attach via PolicyWitness + keepalive (recommended)

```sh
./.venv/bin/python -m book.api.witness.frida \
  --profile-id minimal@injectable \
  --probe-id capabilities_snapshot \
  --script book/api/frida/hooks/smoke.js \
  --out-dir book/api/witness/out \
  --keepalive \
  --frida-helper
```

Outputs:
- `book/api/witness/out/<run_id>/manifest.json`
- `book/api/witness/out/<run_id>/frida/events.jsonl`
- `book/api/witness/out/<run_id>/frida/meta.json`
- Keepalive events: `book/api/witness/out/keepalive/<run_id>/events.jsonl`

## Attach via keepalive only (hold_open)

```sh
./.venv/bin/python -m book.api.witness.keepalive hook-frida \
  --spawn-hold-open \
  --script book/api/frida/hooks/smoke.js \
  --helper
```

This is a good smoke test for the helper and Frida pipeline without PolicyWitness.

## Troubleshooting
- **PermissionDeniedError**: The target is hardened and lacks `get-task-allow` (common when attaching to the base variant).
- **No taskgated logs**: Kernel may deny before `taskgated` runs. Check kernel logs for `macOSTaskPolicy` messages.
- **Invalid entitlements blob**: Re-sign helper with `--generate-entitlement-der`.

## Kernel log capture (optional)

```sh
/usr/bin/log stream --style syslog \
  --predicate 'process == "kernel" && (eventMessage CONTAINS "taskport" || eventMessage CONTAINS "get-task-allow" || eventMessage CONTAINS "macOSTaskPolicy")' \
  --info --debug --timeout 15
```

The kernel message will explicitly state whether the target is hardened and missing `get-task-allow`.
