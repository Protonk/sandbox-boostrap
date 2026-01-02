# Extensions demo – extensions as a third dimension in practice

## Context

- Host: Sonoma baseline (see `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5 (baseline: book/world/sonoma-14.4.1-23E224-arm64/world.json)`).
- Demo: `book/examples/extensions-dynamic/extensions_demo.c`.
- Goal: observe sandbox extensions as a “third dimension” in Seatbelt policy by issuing a `com.apple.app-sandbox.read` extension for a target path, consuming it into the Seatbelt label, and rerunning a `file-read*` operation.

## Symptom

- Prebuilt `HEAD` binary crashes with `Sandbox(Signal 11)` on this host.
- Crash log shows `sandbox_extension_consume` calling `_platform_strcmp` with a NULL pointer; there is no guard on `token == NULL` in that artifact.
- Rebuilt binary (from the same source) runs but sees `rc=0, token=NULL, errno=EPERM` from `sandbox_extension_issue_file` for both a strongly protected path (`/private/var/db/ConfigurationProfiles`) and `/tmp`.

## Reproduction

- `./book/examples/extensions-dynamic/extensions_demo` (prebuilt from `HEAD`):
  - crashes with `Sandbox(Signal(11))`,
  - crash report shows `EXC_BAD_ACCESS` in `_platform_strcmp` from `sandbox_extension_consume`.
- Rebuild and rerun:
  - `clang book/examples/extensions-dynamic/extensions_demo.c -o book/examples/extensions-dynamic/extensions_demo -ldl`
  - run output shows:
    - `open("/private/var/db/ConfigurationProfiles") -> success`,
    - `sandbox_extension_issue_file failed rc=0 errno=1 (Operation not permitted)`,
    - guarded path skips consume/release when `token==NULL`.

## Interpretation

- API behavior:
  - On this host, `sandbox_extension_issue_file` can return `rc=0` but `token=NULL` and set `errno=EPERM` for unentitled callers.
  - Any caller that treats `rc==0` as success and unconditionally consumes the token will dereference NULL via `sandbox_extension_consume`.
- Demo behavior:
  - The prebuilt artifact lacks a `token == NULL` check and crashes; the rebuilt binary includes the guard and exits cleanly when no token is issued.
  - Baseline `open()` on `/private/var/db/ConfigurationProfiles` succeeds without any extension, so the demo does not show a denial→allow transition on this host.
- Seatbelt perspective:
  - Extensions remain modeled as dynamic capabilities attached to the Seatbelt label and referenced via `(extension ...)` filters.
  - Here, the extension issuance path is blocked at the `libsandbox` API/entitlement layer; the label never gains a token, so any branch that depends on `(extension ...)` being true remains unreachable.
  - The effective behavior is dominated by the existing policy stack and adjacent controls (SIP/TCC), not by extension-driven widening.

## Status

- Status: **resolved / understood limitation**.
- For this host and demo:
  - the crash is explained by a missing NULL guard in the prebuilt binary plus the `rc=0, token=NULL, errno=EPERM` API pattern,
  - unentitled, ad-hoc callers cannot obtain a usable `com.apple.app-sandbox.read` extension for the paths tested, so no extension-driven allow is observed.
- Future extension examples should:
  - always guard on both `rc!=0` and `token==NULL`,
  - pick target paths and processes where the baseline operation is denied but the extension is expected to be granted (likely requiring entitlements or a different launch context).

## Pointers

- Source/demo: `book/examples/extensions-dynamic/extensions_demo.c`
- Crash log: `extensions_demo-… .ips` under `~/Library/Logs/DiagnosticReports/` on the host
- Related experiments: `book/experiments/runtime-final-final/suites/runtime-checks` (for other runtime probes)
