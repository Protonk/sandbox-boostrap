# Platform vs app policy

- Seatbelt evaluates the global platform policy before any per-process/App Sandbox profile; a platform deny ends the syscall even if a custom SBPL profile would allow it (Orientation §2).
- Platform rules frequently guard sysctls, Mach services, and SIP-protected paths using filters like `sysctl-name`, `csr`, and `system-attribute` (see guidance/Appendix.md).
- Observing errno from real syscalls only shows the final outcome—you infer platform involvement when seemingly permissive profiles still fail.
- Testing “harmless-looking” operations against system resources is a good way to build intuition about the invisible platform layer that stacks with per-process rules.
- Some failures (especially writes under `/System`) come from SIP/volume sealing before Seatbelt rules run; running the same probes under a custom sandbox can help separate platform policy from immutable-filesystem behavior.
