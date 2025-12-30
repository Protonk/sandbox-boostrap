# Runtime Native Probes

This directory holds small, standalone probe binaries used by the runtime
harness. They are intentionally minimal to keep runtime evidence readable and
to avoid extra syscalls that would confound sandbox decisions.

## Probes

- `mach_probe`: Unsandboxed `bootstrap_look_up` for a service name.
- `sandbox_mach_probe`: Applies SBPL via `sandbox_init`, then performs the same
  lookup (emits tool markers on stderr).
- `iokit_probe`: Unsandboxed `IOServiceMatching` + `IOServiceOpen` for a class,
  followed by minimal post-open calls (selector sweep + `IOSurfaceCreate`) to
  exercise the user-client path. Emits call selector and input/output sizes.
- `sandbox_iokit_probe`: Applies SBPL via `sandbox_init`, then performs the same
  open + post-open calls (emits tool markers on stderr).

## Probe env toggles

- `SBL_IKIT_SKIP_SWEEP=1`: skip the IOConnectCallMethod selector sweep and only
  run the IOSurfaceCreate post-open action.
- `SANDBOX_LORE_IKIT_SELECTOR_LIST=...`: override the selector sweep with a
  comma/space-separated list of method numbers. When set, probes use a small
  non-zero input/output buffer to avoid trivially invalid shapes.
- `SANDBOX_LORE_IKIT_CAPTURE_CALLS=1`: in `iokit_probe`, capture the first
  IOSurfaceCreate-triggered IOKit call (and first non-invalid call) via
  interposed IOConnect/IOKit MIG stubs. Capture mode suppresses the sweep.
- `SANDBOX_LORE_IKIT_CALL_KIND=...`: call kind to use for the sweep/replay
  (`IOConnectCallMethod`, `IOConnectCallScalarMethod`, `IOConnectCallStructMethod`,
  `IOConnectCallAsyncScalarMethod`, `IOConnectCallAsyncStructMethod`,
  `io_connect_method_scalarI_scalarO`, `io_connect_method_scalarI_structureO`,
  `io_connect_method_scalarI_structureI`, `io_connect_method_structureI_structureO`,
  `io_async_method_scalarI_scalarO`, `io_async_method_scalarI_structureO`,
  `io_async_method_scalarI_structureI`, `io_async_method_structureI_structureO`).
- `SANDBOX_LORE_IKIT_CALL_IN_SCALARS=...`: override scalar input count for the
  sweep/replay call shape.
- `SANDBOX_LORE_IKIT_CALL_IN_STRUCT_BYTES=...`: override input struct byte count
  for the sweep/replay call shape.
- `SANDBOX_LORE_IKIT_CALL_OUT_SCALARS=...`: override scalar output capacity for
  the sweep/replay call shape.
- `SANDBOX_LORE_IKIT_CALL_OUT_STRUCT_BYTES=...`: override output struct capacity
  for the sweep/replay call shape.
- `SANDBOX_LORE_IOKIT_ORACLE_ONLY=1`: in `sandbox_iokit_probe`, emit oracle
  callouts and exit before any IOServiceOpen/post-open actions.

## Build

Use the local build script to refresh the binaries in-place:

```sh
book/api/runtime/native/probes/build.sh
```

Outputs are written alongside the sources.
