# Network operation filters

- Network syscalls map to sandbox operations such as `network-outbound`, with filters for `socket-domain`, `socket-type`, and remote/local addresses (substrate/Appendix.md).
- TCP, UDP, and AF_UNIX sockets exercise different combinations of those filters; the same code path looks different to the sandbox depending on domain/type/port/path.
- Outside a sandbox these calls usually succeed (or fail with ECONNREFUSED), but under SBPL rules you can target very specific combinations, making network policy richer than early Seatbelt examples.
- Running a consistent client while changing policy is a good way to see how the filter vocabulary translates to real syscalls.
