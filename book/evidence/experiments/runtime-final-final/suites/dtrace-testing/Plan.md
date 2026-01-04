# dtrace-testing

## Question
Can we capture SIP-compatible, PID-scoped DTrace witnesses for EntitlementJail’s runtime denials and sandbox API usage on the Sonoma 14.4.1 baseline, and normalize those events into stable deny signatures without over-claiming PolicyGraph paths?

## Baseline & scope
- world_id: sonoma-14.4.1-23E224-arm64-dyld-a3a840f9 (`book/world/sonoma-14.4.1-23E224-arm64/world.json`)
- Host scope: macOS Sonoma 14.4.1 (23E224), Apple Silicon, SIP enabled.
- Target: EntitlementJail.app (debuggable XPC service preferred).
- Scope: DTrace syscall denials + libsystem_sandbox API calls, PID-scoped only.
- Out of scope: kernel/fbt providers, cross-version claims, promotion to mappings/CARTON.

## Plan
- Capture EntitlementJail entitlements (main app + debug XPC service) and store raw entitlements output.
- Launch EntitlementJail.app, identify the specific target PID, and record the selection method.
- Use a SIP-compatible probe set (syscall + pid providers) filtered to `pid == $target` with `errno == EPERM || errno == EACCES`.
- Run a smoke capture, an idle baseline capture, and a repeatable interaction capture.
- Preserve raw JSONL traces verbatim; normalize into deny signatures keyed by phase.
- Map observations to existing operations/filters as partial runtime evidence and document any blocked probes.
