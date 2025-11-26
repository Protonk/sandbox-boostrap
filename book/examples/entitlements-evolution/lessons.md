# Entitlement-driven behavior

- Entitlements live in the code signature as metadata; the SBPL profile reads them via filters like `(entitlement-is-present ...)` rather than as variables inside the policy. The same binary produces different sandbox outcomes depending on how it is signed.
- Platform and App Sandbox profiles frequently pair entitlements with other metadata predicates (e.g., `signing-identifier`, `system-attribute`) to gate powerful operations.
- Because entitlements are inputs to the platform policy, a process without them can be denied even if its own per-process profile would otherwise allow the operation (see `substrate/Appendix.md` on filter vocabulary).
- The accompanying program only prints signing ID/entitlements; to see policy effects, run signed vs unsigned (or differently entitled) builds under a sandbox and watch filters like `(entitlement-is-present ...)` and `(signing-identifier ...)` change outcomes.
- Empirically toggling entitlements on the same program is a good way to see how Seatbelt combines platform and per-process policy without changing any runtime code.
