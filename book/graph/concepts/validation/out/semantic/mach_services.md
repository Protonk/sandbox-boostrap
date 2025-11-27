# mach-services probe notes

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
