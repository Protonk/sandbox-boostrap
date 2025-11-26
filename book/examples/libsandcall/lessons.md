# libsandbox compile/apply demo

- Compiles inline SBPL with `sandbox_compile_string`, previews the resulting bytecode header/length, and attempts `sandbox_apply` to show how apply is typically blocked without the right entitlements or SIP context.
- Demonstrates the private APIs described in `substrate/Orientation.md` §3.2; useful for observing how compilation succeeds even when activation (`sandbox_apply`) is refused.
- Expect `sandbox_apply` to return EPERM on modern macOS unless the binary is specially entitled or run in a permissive environment.
