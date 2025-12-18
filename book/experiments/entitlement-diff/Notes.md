# Entitlement Diff – Notes

Use this file for concise notes on signing, profile extraction, and probe runs.

## Entitlement pair setup

- Added sample program `entitlement_sample.c` (binds to 127.0.0.1:56789) and built binaries `entitlement_sample` and `entitlement_sample_unsigned`.
- Created entitlements: `entitlements/network_server.plist` and `entitlements/none.plist`.
- Codesigned both binaries ad-hoc with respective entitlements (`codesign -s - --entitlements ...` succeeded).
- Extracted entitlements to `out/entitlement_sample.entitlements.plist` (contains `com.apple.security.network.server` true) and `out/entitlement_sample_unsigned.entitlements.plist` (empty dict).
- Runtime profile extraction and behavior probes not yet attempted; need to decide how to derive compiled profiles tied to these entitlements (app sandbox template or other pipeline) and a harness that can apply them.

## Wrapper path

- SBPL/Blob wrapper (`book/api/SBPL-wrapper/wrapper`) now available to apply compiled profiles directly. Once we derive App Sandbox SBPL (or compiled blobs) for the signed variants, we can run runtime probes without relying on `sandbox-exec`.
- Next action: pick an App Sandbox template, inject entitlements/params to produce per-variant SBPL, compile via `sandbox_compile_string`, and exercise via the wrapper to observe network server allow/deny deltas.

## Next steps

- Derive App Sandbox SBPL for the signed variants (network_server vs none), compile via libsandbox to blobs, and apply via wrapper (SBPL or blob) for runtime probes. Use simple network/mach probes to capture entitlement-driven deltas. Wrapper path avoids sandbox-exec issues.

## SBPL variants, decode, and runtime probes

- Added App Sandbox stubs under `sb/` with pinned params and *entitlements* for two variants: `appsandbox-baseline.sb` (no network.server, no mach-lookup allowlist) and `appsandbox-network-mach.sb` (network.server plus `com.apple.cfprefsd.agent` mach-lookup). Params use neutral placeholders (e.g., `/private/tmp/entitlement-diff/...`, `_HOME=/Users/entitlement-diff`).
- `build_profiles.py` inlines `book/profiles/textedit/application.sb` and compiles the stub directly (no string rewrite of `(param ...)` / `(entitlement ...)` because the stubs already pin those via Scheme definitions); writes expanded SBPL to `sb/build/*.expanded.sb` and blobs to `sb/build/*.sb.bin`.
- `diff_profiles.py` decodes both blobs with `decoder.decode_profile_dict` and emits `out/decoded_profiles.json` plus `out/profile_diffs.json` (ops present via op_table indices, literal/literal_ref deltas, tag count and tag_literal_ref deltas).
- `run_probes.py` stages `entitlement_sample`, `mach_probe`, and `file_probe` into `/private/tmp/entitlement-diff/app_bundle/` (matching `application_bundle`), with container paths under `/private/tmp/entitlement-diff/container/`. Wrapper probes:
  - baseline: network bind denied (`bind: Operation not permitted`); mach-lookup `com.apple.cfprefsd.agent` allowed; file read/write to container allowed.
  - network_mach: network bind allowed; mach-lookup allowed; file read/write allowed.
  Results captured in `out/runtime_results.json`.
