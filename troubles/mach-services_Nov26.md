

## traces

### mach-services probe notes

- Host: macOS 14.4.1 (23E224), SIP enabled.
- Build: `mach_server`/`mach_client` compiled after falling back to `bootstrap_register` (bootstrap_register2 was undeclared on this SDK). Warning about deprecation is expected.
- Run procedure:
  - Attempted to launch `mach_server` (background) then `mach_client`.
  - Server log: `bootstrap_register("com.example.xnusandbox.demo") failed: unknown error code` (kr=0x44c).
  - Client log: `mach-lookup` for demo service and for system services (`com.apple.cfprefsd.daemon`, `com.apple.securityd`) all returned kr=0x44c.
- Interpretation:
  - kr 0x44c maps to BOOTSTRAP_NOT_PRIVILEGED. Arbitrary service registration/lookup appears blocked at bootstrap level for this process context (likely platform/bootstrap policy, not SBPL alone).
  - No evidence the client ever reached Seatbelt `mach-lookup` filters; failure occurred before a successful registration/lookup.
- Next steps to get a successful witness:
  - Use an allowed/whitelisted service name or run under a context with bootstrap privileges.
  - Launch via a proper launchd plist (per-user domain) to see if registration succeeds there.
  - Instrument with logging (if possible) to confirm whether Seatbelt hooks are reached when bootstrap succeeds.

### jsonl

```
{"service": "com.example.xnusandbox.demo", "server_register": "failed", "kr_register": "0x0000044c", "kr_meaning": "BOOTSTRAP_NOT_PRIVILEGED", "note": "bootstrap_register failed; client lookup also failed"}
{"service": "com.example.xnusandbox.demo", "client_lookup": "failed", "kr": "0x0000044c", "kr_meaning": "BOOTSTRAP_NOT_PRIVILEGED", "note": "Server not registered; platform/bootstrap may block arbitrary names for unprivileged callers"}
{"service": "com.apple.cfprefsd.daemon", "client_lookup": "failed", "kr": "0x0000044c", "kr_meaning": "BOOTSTRAP_NOT_PRIVILEGED", "note": "Lookup denied/failed without sandbox profile"}
{"service": "com.apple.securityd", "client_lookup": "failed", "kr": "0x0000044c", "kr_meaning": "BOOTSTRAP_NOT_PRIVILEGED", "note": "Lookup denied/failed without sandbox profile"}
```

## Agent notes

- Rebuilt `mach_server` and `mach_client` with `clang` (bootstrap_register fallback still in use; deprecation warning expected). Environment: macOS 14.4.1 (23E224), SIP enabled.
- Direct runs after rebuild:
  - `mach_server` prints `bootstrap_register("com.example.xnusandbox.demo") failed: unknown error code` and exits 1.
  - `mach_client` reports `kr=0x44c` for the demo service and for `com.apple.cfprefsd.daemon` / `com.apple.securityd`.
- Decoded `0x44c` via `bootstrap_strerror` (python3 + ctypes): `Permission denied` (matches `BOOTSTRAP_NOT_PRIVILEGED`). Suggests failure in the bootstrap/launchd layer before Seatbelt `mach-lookup` filters would run.
- Tried to run the server under launchd to see if a managed per-user job gains bootstrap privileges:
  - `launchctl bootstrap gui/$UID /tmp/com.example.xnusandbox.demo.plist` → `Bootstrap failed: 5: Input/output error`.
  - `launchctl submit -l com.example.xnusandbox.demo -- /Users/achyland/Desktop/SANDBOX_LORE/book/examples/mach-services/mach_server` → exit 1, no job present (`launchctl print gui/$UID` shows nothing).
- Current state: both ad-hoc and launchd-invoked attempts are blocked at bootstrap registration/lookup with `BOOTSTRAP_NOT_PRIVILEGED`. No evidence that mach-lookup reached Seatbelt policy graphs; this remains an upstream bootstrap policy issue rather than an SBPL allow/deny result.

## from chat

When asked if this is expected:

Yes. From the substrate lens, mach-lookup is mediated by two layers: Seatbelt’s mach-lookup operation/(global-name ...) filters, and the bootstrap/launchd policy in front of it. Platform/bootstrap rules are a high‑churn surface and often deny arbitrary registration and lookup by unprivileged callers. Seeing BOOTSTRAP_NOT_PRIVILEGED before Seatbelt ever evaluates the mach-lookup graph is therefore consistent with what we’d expect on a stock macOS 13–14 system with SIP enabled: the bootstrap gate refuses the request, so the sandbox never gets a say. A successful demo would require a whitelisted name and/or a launch context that is allowed to register/lookup (e.g., via a proper per‑user launchd job or an entitlement), which matches the “platform policy may still deny” caveat in the example text.

