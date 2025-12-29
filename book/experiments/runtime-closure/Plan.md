# Runtime Closure – Plan (Sonoma baseline)

## Purpose

Provide narrow, stage-labeled runtime evidence that closes gaps in `probe-op-structure` by separating:

- **Path canonicalization effects** (e.g., `/etc/hosts` vs `/private/etc/hosts`).
- **Mach service existence vs sandbox denial** (known existing vs known missing service names).
- **IOKit class presence vs sandbox denial** (class present + openable vs class missing).

This experiment is intentionally small and uses only plan/registry data + the shared runtime harness. It is a runtime companion to the structural anchor work in `book/experiments/probe-op-structure/`.

## Stage taxonomy

Every run is interpreted by stage:

- **Compile**: SBPL source -> compiled blob (construction errors only).
- **Apply**: compiled blob -> sandbox applied (apply-gate or already-sandboxed failures only).
- **Exec**: harness viability under the sandbox (self-denials, missing deps).
- **Operation**: the probed syscall/IPC/IOKit operation (only this stage is eligible for mapped promotion when paired with a structural anchor binding).

## Lanes and questions

1) **File canonicalization lane**
   - Profiles: alias-only, private-only, and data-only spellings (literal-only rules).
   - Probes: `/etc/hosts`, `/private/etc/hosts`, `/System/Volumes/Data/private/etc/hosts`, plus the same three spellings for `/tmp/foo` under each profile.
   - Question: which spelling is enforced at operation time for `/etc` and `/tmp` (alias vs `/private` vs Data firmlink)?

2) **Mach service discrimination lane**
   - Profile: allow `mach-lookup` for one known service and one intentionally missing name.
   - Probes: existing service (`com.apple.cfprefsd.agent`) + missing control (`com.apple.sandbox-lore.missing`).
   - Question: is a failure a true denial or a missing service (baseline vs scenario)?

3) **IOKit op-identity lane**
   - Profiles: `iokit-open-service` only, `iokit-open-user-client` only, and both (deny-witness tri-matrix).
   - Probes: `IOSurfaceRoot` with a post-open user-client call (IOConnectCallMethod).
   - Question: which IOKit operation gates service open vs post-open user-client use on this host?

## Evidence and artifacts

- Runtime plan/registry: `plan.json`, `registry/probes.json`, `registry/profiles.json`.
- SBPL profiles: `sb/*.sb` (compiled automatically by the runtime harness).
- Runtime bundles: `out/<run_id>/` with `runtime_results.json`, `runtime_events.normalized.json`, `path_witnesses.json` (when available), `run_manifest.json`, and `artifact_index.json`.

## Guardrails

- Preflight scan every SBPL profile with `book/tools/preflight/preflight.py scan` before runtime runs.
- Use `launchd_clean` channel only for decision-stage evidence.
- Treat apply-stage EPERM as **blocked**, not policy semantics.

## Relationship to probe-op-structure

This experiment feeds runtime closure for anchors already in `probe-op-structure` (notably `/etc/hosts`, `com.apple.cfprefsd.agent`, and IOKit class probes). Results are recorded here and summarized back into `probe-op-structure/Notes.md` and `Report.md` as runtime context.
