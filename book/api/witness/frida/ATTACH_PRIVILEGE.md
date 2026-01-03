# PolicyWitness Frida Attach Privilege Plan

Baseline scope: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.

This plan is an operational guide, not evidence. It does not weaken the baseline (no SIP/TCC changes, no hardened runtime changes).

## Why attach fails (expected)
PolicyWitness runs sandboxed XPC services with debug-heavy entitlements. Frida attach uses `task_for_pid` under the hood, which is restricted on macOS. When attach is denied, the expected symptom is `PermissionDeniedError: unable to access process with pid ...`.

## Plan (minimum surface)
1) Preflight the local environment.
   - Use `python -m book.api.witness.frida.preflight` to capture a JSON report of the Python runtime, Frida import, and codesign entitlements for the current interpreter.
   - If you want to test attach, pass `--pid` (this is a live attach attempt and may need escalation).

2) Validate Frida on an unprivileged target first.
   - Use the keepalive CLI to attach to `hold_open` and confirm a clean Frida trace.
   - This checks the Frida runtime and the keepalive hook flow before dealing with PolicyWitness restrictions.

3) PolicyWitness attach path (expected to require privilege).
   - The likely requirement is a debugger entitlement on the runner (commonly `com.apple.security.get-task-allow`). I do not know the minimal entitlement set for this host; treat this as the expected starting point and confirm with `codesign -d --entitlements :- <binary>`.
   - If the runner is not entitled, run the Frida attach from a signed helper or signed Python interpreter that carries the required entitlements. The helper lives at `book/api/frida/native/attach_helper` with an entitlements template in `entitlements.plist`.
   - If developer tools authorization is required, use the system developer tools flow (Xcode/CLT) and avoid any baseline-weakening steps.

4) Record outcomes explicitly.
   - For each attempt, record `stage=operation` and `lane=oracle` plus a one-line limits note (for example: "attach denied, no policy conclusions").

## Suggested commands (operational only)
- Preflight:
  - `python -m book.api.witness.frida.preflight`
  - `python -m book.api.witness.frida.preflight --pid <pid>`
- Keepalive Frida smoke:
  - `python -m book.api.witness.keepalive hook-frida --spawn-hold-open --script book/api/frida/hooks/smoke.js`
  - `python -m book.api.witness.keepalive hook-frida --spawn-hold-open --script book/api/frida/hooks/smoke.js --helper`

## Limits
This plan does not guarantee attach success; it only defines the expected privilege surface and safe checks. If attach still fails, treat the outcome as a privilege limitation, not a PolicyWitness defect.
