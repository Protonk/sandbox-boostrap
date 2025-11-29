# Entitlement-Driven Profile Differences

## Goal

Show how specific entitlements change compiled profiles and filters/parameters, and how those changes affect runtime behavior. Produce diffs that connect entitlements → SBPL parameters/filters → compiled graph → allow/deny behavior.

## Scope

- Pick a small set of entitlements that are known to toggle sandbox capabilities (e.g., network server/client, mach-lookup exceptions, file access).
- Build two or three binaries (unsigned vs signed with entitlement; optional alternate entitlement) using minimal code.
- Outputs: extracted entitlements, compiled profiles, decoded filter/param deltas, and runtime probe logs where feasible.

## Steps

1) **Select entitlements**
   - Choose 2–3 candidate keys (e.g., `com.apple.security.network.server`, a mach-lookup entitlement, a file-access entitlement if available).

2) **Build variants**
   - Create a tiny C program (e.g., prints entitlements and opens a test resource).
   - Sign variants with/without each entitlement (or ad-hoc where possible).

3) **Compile and decode profiles**
   - Extract compiled profiles associated with each variant (via libsandbox compile or system tooling).
   - Decode with `profile_ingestion.py` and diff filters/parameters to show entitlement-driven changes.

4) **Runtime probes (if allowed)**
   - Run simple probes (file/network/mach) under each variant and log allow/deny results. Use `book/api/SBPL-wrapper/wrapper` (SBPL or blob) instead of `sandbox-exec` where possible. Note if SIP/TCC block runtime on this host; rerun in a permissive environment if needed.

5) **Summarize deltas**
   - Produce a short manifest showing entitlement → filter/param changes → observed behavior, with OS/build metadata.

Status: binaries and entitlements captured; need a method to derive/apply sandbox profiles that reflect the entitlements (e.g., App Sandbox template) before runtime probes. Wrapper is available once profiles are derived.

## Done criteria

- At least one entitlement with a clear profile/filter delta demonstrated across signed variants.
- Decoded diffs and (if possible) runtime logs linked in a manifest.
- Notes on environment constraints (e.g., SIP, signing requirements).
