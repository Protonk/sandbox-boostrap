# ERRATA 

Places where hands-on work on macOS 14.x diverged from, or added nuance to, the Orientation.md / Appendix.md framing.

## Errata noted during modernization.

### Sandbox apply vs compile
- Observation: `sandbox_apply` exists in `libsandbox.dylib` but returns `EPERM` on stock macOS 14.4 without special entitlements (libsandcall HISTORY 2025-11-23: modern-call-demo).
- Orientation says Stage 3 “Kernel install” accepts compiled profiles; in practice, unprivileged apply is blocked by SIP/entitlements. Compilation remains accessible; enforcement activation is gated.

### Public headers and symbols
- Orientation assumes compiler APIs exist; public SDK headers (`sandbox.h`) do not declare `sandbox_compile_*`, but the symbols are present in `libsandbox.dylib` and must be prototyped locally (apple-scheme, sb, sbsnarf updates).
- Tooling that expected `/usr/lib/libsandbox.dylib` or `/System/Library/Extensions/Sandbox.kext` symbol extraction (sbdis find_operations) no longer works: Sandbox.kext binary not present at that path on macOS 14.x, breaking automated operation-name discovery.

### Format detection and re_table_offset
- Orientation/Appendix describe both early decision-tree and later graph formats. Modern compiled blobs from `sandbox_compile_*` report `re_table_offset = 0` (sbdis run-demo failure), which the legacy parser treats as unsupported. This suggests a newer storage/layout than the early format; graph-based support is needed.

### sandbox-exec availability
- Orientation mentions `sandbox-exec` as a userland launcher; on macOS 14.4, `sandbox-exec` invocation fails with `sandbox_apply: Operation not permitted` even for trivial profiles (apple-scheme HISTORY). User-facing enforcement via sandbox-exec is effectively blocked; compilation via libsandbox still works.

### Parameterized profiles
- Many system profiles use `(param ...)` and string-append; compilation without supplying parameters fails (e.g., `application.sb` → “string-append: argument 1 must be: string”). Orientation notes parameters implicitly via Sandbox DSL, but practical usage requires passing parameters into `sandbox_compile_file` (handled in extract_sbs with `--param`).

### AppleMatch access
- Orientation/Appendix treat regex tables as accessible; on macOS 14.x the `libMatch` userland library used by the old C tool is not readily available. Pure-Python parsing (re2dot) fills the gap; reliance on system library is not viable.

### Storage locations
- Orientation covers kernelcache/bundle storage evolution; on macOS 14.x profiles live under `/System/Library/Sandbox/Profiles` and can be compiled directly. The kernelcache offset scraping path is obsolete (extract_sbs modern replacement).
