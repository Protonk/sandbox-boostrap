# Notes

- Initialized hardened-runtime scaffold; first clean-channel run recorded with decision-stage events and mismatch packets.
- Added notification probes (darwin + distributed post) as a third non-VFS family; allow probes currently deny under the hardened profile, captured as mismatch packets.
- Added signal canary using a child process (same-sandbox target) with allow/deny profiles; allow and deny now match under the clean channel.
- Added allow-canary profiles per family (mach/sysctl/notifications/process-info) and recorded dependency-denial fields in runtime results.
- Added schema versions and artifact index metadata to hardened-runtime outputs for stable consumption.
- Regenerated `other_runtime_inventory.json` to reflect runtime probe migration into `book/api/runtime/native/probes`.
