# Entitlement Diff – Research Report

## Purpose

Trace how selected entitlements alter compiled sandbox profiles and the resulting allow/deny behavior. Ground the entitlement concept in concrete profile/filter/parameter changes and, where possible, runtime probes.

## Baseline

- Host: TDB (record OS/build/SIP when runs are performed).
- Tooling: small C sample, signing via `codesign`, profile decoding via `profile_ingestion.py`.
- Entitlements: to be selected (network server/client, mach-lookup exceptions, file access candidates).

## Status

- Sample program added (`entitlement_sample.c`) and built as `entitlement_sample` (ad-hoc signed with `com.apple.security.network.server`) and `entitlement_sample_unsigned` (signed with empty entitlements).
- Entitlements extracted to `out/entitlement_sample.entitlements.plist` and `..._unsigned.entitlements.plist` (network.server present vs empty).
- Next steps: derive or synthesize compiled sandbox profiles that reflect these entitlements (e.g., via app sandbox template) and run probes to see behavioral deltas; use the SBPL/Blob wrapper once profiles exist to avoid the earlier `sandbox-exec` roadblock. Current blocker: generating per-entitlement profiles.
