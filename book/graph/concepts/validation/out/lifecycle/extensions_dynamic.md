# extensions-dynamic probe notes

- Attempted to run `book/examples/extensions-dynamic/extensions_demo` (libsandbox extension issuance/consume demo) on macOS 14.4.1 (23E224), SIP enabled.
- Outcome: process crashes with `Sandbox(Signal 11)` (exit 139) even after adding guards to skip consume/release when issuance fails.
- lldb attempts (`lldb -- ./extensions_demo` with `run`/`bt`) failed to attach because process exits before tracing; dtruss blocked by SIP. Token issuance via isolated Python/ctypes calls returns `rc=0` with `token=NULL` for both `/private/var/db/ConfigurationProfiles` and `/tmp`, suggesting libsandbox may be returning success with null tokens for unentitled callers.
- Hypothesis: demo crashes inside libsandbox when dereferencing/processing a NULL token or due to missing entitlement context. Next steps would be to:
  - Run under a debugger with SIP disabled or in a dev mode that allows tracing.
  - Adjust target path to something less protected or use a different extension class.
  - Mock the extension issuance/consume flow to avoid calling into libsandbox on unentitled binaries.
