

## Summary so far

- Two binaries exist: the prebuilt `HEAD` artifact (`/tmp/extensions_demo.head`) still crashes with `Sandbox(Signal 11)`; a fresh rebuild from source runs and exits cleanly after seeing `token=NULL`.
- Crash log `extensions_demo-2025-11-26-202649.ips` shows `sandbox_extension_consume` calling `_platform_strcmp` with `x0=0`, i.e., a NULL token path; this matches the behavior seen when libsandbox returns `rc=0, token=NULL`.
- Disassembly confirms the crashing binary lacks a guard on `token == NULL`; it proceeds to consume unconditionally when `rc==0`. The rebuilt binary includes the guard and skips consume/release when `token` is NULL.
- libsandbox on this host (macOS 14.4.1, SIP enabled) returns `rc=0, token=NULL, errno=EPERM` for `sandbox_extension_issue_file("com.apple.app-sandbox.read", "/private/var/db/ConfigurationProfiles", 0, &token)` and also for `/tmp`. This matches prior ctypes notes and explains the NULL deref.
- Baseline `open()` to `/private/var/db/ConfigurationProfiles` succeeds here, so the demo does not illustrate a denial→allow transition even when the crash is avoided.

## Reproduction notes

- `./book/examples/extensions-dynamic/extensions_demo` (prebuilt from `HEAD`):
  - Crash: `Sandbox(Signal(11))`.
  - Crash log excerpt: `EXC_BAD_ACCESS (SIGSEGV) KERN_INVALID_ADDRESS at 0x0`, faulting in `_platform_strcmp` invoked from `sandbox_extension_consume` → `main`.
  - `usedImages`: `libsystem_sandbox.dylib` is the caller; SIP enabled; macOS 14.4.1 (23E224).
- `clang book/examples/extensions-dynamic/extensions_demo.c -o book/examples/extensions-dynamic/extensions_demo -ldl` (fresh build):
  - Run output:
    - `open("/private/var/db/ConfigurationProfiles") -> success (fd=3)`
    - `sandbox_extension_issue_file failed rc=0 errno=1 (Operation not permitted)`
    - Skips consume/release; exits normally.

## Root cause hypothesis

- The crash stems from calling `sandbox_extension_consume` with a NULL token. The prebuilt binary was compiled before the null-token guard landed (or with different optimization/layout that elided the guard).
- libsandbox returns “success” (rc=0) but no token for unentitled callers, so any code path that treats `rc==0` as sufficient will dereference NULL inside `sandbox_extension_consume`.

## Suggested fixes/documentation for this probe

- Always rebuild before running (or remove the prebuilt binary from version control) to ensure the null-token guard is present.
- Treat both `rc!=0` and `token==NULL` as hard failure; skip consume/release in that case.
- Capture the current behavior as expected for unentitled callers: `rc=0, token=NULL, errno=EPERM`.
- If we want a denial→allow demonstration, wrap the demo in a sandbox profile that denies the target path or pick a path that the current label cannot open; otherwise the baseline `open` succeeds.
- If deeper debugging of libsandbox behavior is needed, it likely requires entitlements or SIP-off tracing; alternatively, mock token issuance to illustrate the API without touching libsandbox.

## Detailed trace log

- `./book/examples/extensions-dynamic/extensions_demo` → `Sandbox(Signal(11))`.
- `lldb -- ./book/examples/extensions-dynamic/extensions_demo` could not attach (process exits before stop).
- `clang book/examples/extensions-dynamic/extensions_demo.c -o book/examples/extensions-dynamic/extensions_demo -ldl` then rerun → no crash; sees `rc=0, token=NULL, errno=1`.
- `git show HEAD:book/examples/extensions-dynamic/extensions_demo > /tmp/extensions_demo.head; chmod +x` → `/tmp/extensions_demo.head` crashes with `Sandbox(Signal(11))`.
- Crash log `extensions_demo-2025-11-26-202649.ips`:
  - Exception: `EXC_BAD_ACCESS (SIGSEGV) KERN_INVALID_ADDRESS 0x0`
  - Faulting frame: `_platform_strcmp` called from `sandbox_extension_consume`
  - Register state shows `x8` (consume fn) and `x0=0`, consistent with NULL token deref.
- SHA256 diff: prebuilt `HEAD` binary `47acae…f8` vs rebuilt `41910c…e7a`.
- Disassembly:
  - Prebuilt (`/tmp/extensions_demo.head`): on `rc==0` branch, immediately calls `sandbox_extension_consume` without checking `token`.
  - Rebuilt (`book/examples/extensions-dynamic/extensions_demo`): includes `token == NULL` check; skips consume when NULL.
- libsandbox location:
  - `nm` on `/usr/lib/libsandbox.dylib` fails (path not present); symbols resolved at runtime via `dlsym` against `libsystem_sandbox.dylib` from the shared cache (`usedImages` in crash log).
