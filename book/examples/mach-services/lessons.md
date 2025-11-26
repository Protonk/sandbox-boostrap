# Mach services and mach-lookup

- `mach-lookup` is a first-class sandbox operation; SBPL filters on `(global-name "...")` or related predicates to control which bootstrap services a process can talk to.
- Platform policy may deny lookups/registrations regardless of per-process profiles—especially for privileged services like `com.apple.securityd`.
- Watching success/failure against different names shows how service strings become sandbox inputs, matching the operation/filter vocabulary in substrate/Appendix.md.
- Even without full message handling, registering a name and trying to look it up mirrors the kernel path that Seatbelt protects via the policy graph.
- Lookup failures can also reflect bootstrap namespace limits or missing services, so compare runs under different sandbox profiles to distinguish policy from “service not present”.
