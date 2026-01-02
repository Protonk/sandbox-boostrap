# metadata-runner (Report)

## Purpose
- Capture a host witness for metadata-only Operations across alias vs canonical paths.
- Keep metadata canonicalization evidence separate from data read/write behavior (see `book/experiments/vfs-canonicalization/Report.md`).

## Baseline & scope
- Host baseline: sonoma-14.4.1-23E224-arm64-dyld-2c0602c5 with SIP enabled.
- Scope: `file-read-metadata` and `file-write*` across `/tmp/*` <-> `/private/tmp/*` and `/var/tmp/canon` <-> `/private/var/tmp/canon`, covering literal/subpath/regex anchor forms.

## How to run
Run via the runtime CLI so the committed bundle is the only authority (`out/LATEST` is convenience only):

```sh
python -m book.api.runtime run \
  --plan book/experiments/metadata-runner/plan.json \
  --channel launchd_clean \
  --out book/experiments/metadata-runner/out
```

Optional promotion packet (consumer boundary):

```sh
python -m book.api.runtime emit-promotion \
  --bundle book/experiments/metadata-runner/out/LATEST \
  --out book/experiments/metadata-runner/out/promotion_packet.json
```

## How it works
- The plan/registry define a matrix of metadata syscalls (lstat/getattrlist/setattrlist/fstat + chmod/utimes/fchmod/futimes/lchown/fchown/fchownat/lutimes) across alias/canonical paths.
- The runtime harness uses `book/api/runtime/native/metadata_runner` (self-apply) to execute per-probe syscalls under SBPL profiles.
- Baseline lane proves operation-stage reachability without apply gating; scenario lane carries the profile-specific results; alias-only profiles act as the negative-control family (expected to deny across alias/canonical on this host).

## How we will know it works
- A committed bundle exists with `artifact_index.json` and `runtime_events.normalized.json`.
- Scenario lane produces operation-stage evidence for canonical paths under canonical-only profiles; alias-only profiles remain deny.
- Baseline lane results show probes can reach operation stage without apply-stage failures.

## Evidence & artifacts
- Plan: `book/experiments/metadata-runner/plan.json`.
- Registry: `book/experiments/metadata-runner/registry/probes.json`, `book/experiments/metadata-runner/registry/profiles.json`.
- Runtime bundle authority: `book/experiments/metadata-runner/out/<run_id>/artifact_index.json`.
- Normalized events: `book/experiments/metadata-runner/out/<run_id>/runtime_events.normalized.json`.
- Raw results: `book/experiments/metadata-runner/out/<run_id>/runtime_results.json`.
- SBPL sources: `book/experiments/metadata-runner/sb/metadata_*.sb`.
- Optional promotion packet: `book/experiments/metadata-runner/out/promotion_packet.json`.

## Current observations (host-scoped)
- Alias-only profiles deny; canonical-only profiles allow canonical paths and deny aliases.
- Literal-both paths still deny alias requests; subpath-both and regex-both allow `/tmp/*` aliases while `/var/tmp/canon` remains denied.
- `setattrlist` is unstable (`EINVAL` on canonical paths, `EPERM` on aliases) and should be treated as a noisy witness.

## Blockers / risks
- `file-write-metadata` is not in SBPL vocab; metadata writes are proxied via `file-write*` and can be confounded by OS permissions (e.g., chown).
- Anchor form influences alias handling; treat anchor type as a key variable rather than a nuisance.

## Next steps
- Re-run via the unified runtime CLI to refresh the bundle and capture a promotion packet if a consumer needs it.
- Add a narrow allow/deny expectation guardrail once the syscall surface stabilizes.
- Investigate why literal-both paths deny aliases while subpath/regex allow `/tmp/*` aliases.
