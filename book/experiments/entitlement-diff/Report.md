# Entitlement Diff – Research Report

## Purpose
Trace how selected entitlements alter compiled sandbox profiles and the resulting allow/deny behavior. Ground the entitlement concept in concrete profile/filter/parameter changes and, where possible, runtime probes.

## Baseline & scope
- Host: TDB (record OS/build/SIP when runs are performed).
- Tooling: small C sample, signing via `codesign`, profile decoding via `profile_ingestion.py`.
- Entitlements: to be selected (network server/client, mach-lookup exceptions, file access candidates).

## Deliverables / expected outcomes
- Minimal C sample and signed variants (`entitlement_sample`, `entitlement_sample_unsigned`) with extracted entitlements recorded in `out/*.entitlements.plist`.
- A workable method (still to be completed) for deriving per-entitlement App Sandbox profiles suitable for decoding and comparison.
- Planned diffs that connect entitlement keys → SBPL parameters/filters → compiled graph deltas → runtime allow/deny behavior.
- A short manifest tying binaries, profiles, decoded diffs, and probe logs together for this host.

## Plan & execution log
### Completed
- **Current status**
  - Sample program added (`entitlement_sample.c`) and built as `entitlement_sample` (ad-hoc signed with `com.apple.security.network.server`) and `entitlement_sample_unsigned` (signed with empty entitlements).
  - Entitlements extracted to `out/entitlement_sample.entitlements.plist` and `..._unsigned.entitlements.plist` (network.server present vs empty).
  - Next steps: derive or synthesize compiled sandbox profiles that reflect these entitlements (e.g., via app sandbox template) and run probes to see behavioral deltas; use the SBPL/Blob wrapper once profiles exist to avoid the earlier `sandbox-exec` roadblock. Current blocker: generating per-entitlement profiles.
  - Updated harness plan: compile App Sandbox SBPL per entitlement variant and apply via wrapper for runtime probes (network/mach). SBPL path should avoid sandbox-exec issues; need to produce the per-entitlement SBPL first.

### Planned
- Show how specific entitlements change compiled profiles and filters/parameters, and how those changes affect runtime behavior. Produce diffs that connect entitlements → SBPL parameters/filters → compiled graph → allow/deny behavior.
  
  
  - Pick a small set of entitlements that are known to toggle sandbox capabilities (e.g., network server/client, mach-lookup exceptions, file access).
  - Build two or three binaries (unsigned vs signed with entitlement; optional alternate entitlement) using minimal code.
  - Outputs: extracted entitlements, compiled profiles, decoded filter/param deltas, and runtime probe logs where feasible.
  
  
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
  
  
  - At least one entitlement with a clear profile/filter delta demonstrated across signed variants.
  - Decoded diffs and (if possible) runtime logs linked in a manifest.
  - Notes on environment constraints (e.g., SIP, signing requirements).

## Evidence & artifacts
- Source and build scaffolding for `entitlement_sample` under this experiment directory.
- Extracted entitlements in `book/experiments/entitlement-diff/out/entitlement_sample*.entitlements.plist`.
- Notes in `Notes.md` describing signing commands, entitlement choices, and the intended harness.

## Blockers / risks
- No reliable pipeline yet from entitlements → concrete App Sandbox profiles on this host; generating per-entitlement profiles is the main blocker.
- Runtime probes depend on the SBPL/Blob wrapper and may still encounter SIP/TCC or sandbox-apply gates once profiles exist.

## Next steps
- Derive or obtain App Sandbox SBPL templates for the existing signed/unsigned variants (or closely matching profiles) and compile them for this host.
- Decode and diff the resulting profiles with `profile_ingestion.py`, focusing on filter/parameter changes driven by entitlements.
- Run a small set of runtime probes (file/network/mach) under each variant using the SBPL/Blob wrapper and record behavioral deltas.
- Summarize at least one entitlement with a clear profile/filter delta and, if possible, observable runtime behavior.
# Entitlement Diff – Research Report (Sonoma baseline)

## Purpose
Compare entitlements, derived App Sandbox SBPL, compiled profiles, and (eventually) runtime behavior for matched binaries on this host. The goal is to turn specific entitlement changes into observable differences in compiled policy and, where possible, runtime allow/deny behavior.

## Baseline & scope
- Host: Sonoma baseline from `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5 (baseline: book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json)`.
- Inputs: signed binaries with and without specific entitlements, their extracted entitlements plists, and any derived SBPL/profiles.
- Tooling: codesign/entitlement extraction helpers, `book.api.sbpl_compile`, and decoder tooling where profile blobs are available.

## Deliverables / expected outcomes
- A small set of entitlement pairs (with/without, or before/after) with:
  - entitlement manifests under `out/entitlement_manifest.json` (or similar),
  - any derived SBPL or compiled profiles under `out/`,
  - notes on structural differences in compiled profiles where they can be obtained.
- Clear notes in this Report and in `Notes.md` about which parts of the pipeline are currently blocked (for example, profile derivation from entitlements).

## Plan & execution log
### Completed
- Experiment scaffolded (Plan, Notes, this Report).
- Initial entitlement extraction runs completed for at least one binary pair; manifests captured under `out/` and referenced from `Notes.md`.
- Pipeline status recorded: entitlement comparison is working; SBPL/profile derivation from entitlements remains blocked on missing tooling and platform behavior on this host.

### Maintenance / rerun plan
As entitlement tooling improves, reuse this outline:

1. **Scope and setup**
   - Confirm the host baseline in `book/world/.../world-baseline.json`, this Report, and `Notes.md`.
   - Choose a small set of binaries where entitlement changes are well-understood and reproducible.
2. **Entitlement extraction and diff**
   - Extract entitlements for each binary and write a manifest under `out/entitlement_manifest.json` (or per-pair files).
   - Record diffs in `Notes.md` and summarize them here.
3. **Profile derivation (when available)**
   - Once the pipeline exists, derive App Sandbox SBPL and compiled profiles from those entitlements and decode them.
   - Capture structural differences (operations, filters, profile layers) in `out/` and summarize them in this Report.

## Evidence & artifacts
- Entitlement manifests under `book/experiments/entitlement-diff/out/` (file names documented in `Notes.md`).
- Any SBPL or compiled profile blobs derived from those entitlements as the pipeline comes online.

## Blockers / risks
- There is not yet a complete, reliable pipeline from entitlements → App Sandbox SBPL → compiled profile on this host; most structural comparisons remain “planned” rather than implemented.
- Platform behavior and signing/hardening constraints may limit which binaries can be safely used for repeatable comparisons.

## Next steps
- Tighten the entitlement manifest format and keep it stable under `out/`.
- Once SBPL/profile derivation is available, run a first end-to-end pair (with/without a single entitlement) and document structural differences.
