# runtime-mac_policy – kext probe concept

This file captures a kext-probe path to collect runtime evidence for `mac_policy_register` on a host where kext loading and kernel text patching are permitted.

## Prereqs / constraints
- Load a minimal signed kext and modify/branch from kernel text.
- SIP/AMFI must allow the kext and transient text modification.
- Know the live BootKC/sandbox kext hashes/UUIDs and the KASLR slide at runtime.

## Hook shape
- Resolve `mac_policy_register` from the live kernel (keepsyms/ksldebug or precomputed offset + KASLR slide).
- Patch entry with a PAC-safe trampoline:
  - Save displaced instructions (2–3).
  - Replace with a branch to a stub; stub logs then jumps back after the displaced instructions.
  - Obey W^X (make page writable briefly, then restore); flush I-cache.
- Alternative: use a veneer that BLs to the stub, which replays displaced instructions and branches back to the original flow.

## Data to log (per entry)
- Registers: x0 (`mpc`), x1 (`handlep`), x2 (`xd`), LR (call site; strip PAC), target address/image/segment.
- Caller classification: infer from LR range (kernel text vs `com.apple.security.sandbox` vs other).

## Kernel memory reads
- From the stub (or immediately after):
  - Copy 10–12 qwords from `mpc` into a buffer; bail on faults/invalid pointers.
  - If `mpc_name`/`mpc_fullname` look sane, read bounded ASCII strings.
  - If `mpc_ops` is non-NULL, read first N entries (e.g., 64–128 qwords); for each non-NULL entry, strip PAC and record address + owning image/segment.
- Store into a bounded ring buffer in kernel; export via sysctl/IORegistry/devnode for userland normalization.

## Alignment metadata
- Log KASLR slide, BootKC UUID/hash, sandbox kext UUID/hash, and the binary ranges used for image/segment classification.
- In userland, keep a small static op-table index (from `book/graph/mappings/op_table/op_table.json`) to compare representative indices against captured `mpc_ops` without re-running the probe.

## Safety notes
- Minimize instruction patching; verify alignment and cache sync after writes.
- PAC handling: strip PAC on code pointers before classification (`xpaclri`/`autia` as appropriate).
- Keep hooks lightweight (no printf); defer formatting to userland; bound buffers to avoid overruns.

### Current tooling and status
- Capture wrapper (`capture.py`) generates a minimal DTrace script on the fly (provider + function) and normalizes output via `normalize.py` into `out/runtime_mac_policy_registration.json`.
- SIP disabled on the runtime VM; `fbt` available.
- Pipeline proven with `fbt`: `mach_kernel:vnode_put:entry` + `--run-command "/bin/ls /"` + `--exit-after-one` → `out/raw/fbt_smoketest.log`, `out/fbt_smoketest.json` (one EVENT line).
- mac_policy_register target exists in `fbt` (`mach_kernel:mac_policy_register:{entry,return}`), but captures (`out/raw/mac_policy_register_min.log` / `out/mac_policy_register_min.json` with `/bin/ls /`; `out/raw/mac_policy_register_sleep.log` / `out/mac_policy_register_sleep.json` with `sleep 5`) produced zero events; registration occurs before attach and no dynamic MACF policies register later on this host.
- Status: design-only on this host; runtime registration evidence is blocked by timing. Tooling retained for a future runtime world where registration can be observed or where a kext/debugger track is acceptable.
