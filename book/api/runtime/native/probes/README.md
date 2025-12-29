# Runtime Native Probes

This directory holds small, standalone probe binaries used by the runtime
harness. They are intentionally minimal to keep runtime evidence readable and
to avoid extra syscalls that would confound sandbox decisions.

## Probes

- `mach_probe`: Unsandboxed `bootstrap_look_up` for a service name.
- `sandbox_mach_probe`: Applies SBPL via `sandbox_init`, then performs the same
  lookup (emits tool markers on stderr).
- `iokit_probe`: Unsandboxed `IOServiceMatching` + `IOServiceOpen` for a class.
- `sandbox_iokit_probe`: Applies SBPL via `sandbox_init`, then performs the same
  IOKit open (emits tool markers on stderr).

## Build

Use the local build script to refresh the binaries in-place:

```sh
book/api/runtime/native/probes/build.sh
```

Outputs are written alongside the sources.
