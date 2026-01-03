# vfs-canonicalization — Remaining experiments (Sonoma baseline)

This plan lists only the **remaining** and **expanded** experiments for `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`. `Report.md` now contains decision-bounded conclusions for the previously “partial” families; this file focuses on follow-on work that can tighten interpretation and reduce future ambiguity.

## 1) Strengthen the `openat(2)` axis (reduce dependence on caller-supplied absolute strings)

Current `openat(2)` probes split an absolute target path into `(parent_dir, leafname)` and then perform `open(parent_dir)` + `openat(dirfd, leafname, ...)`. This still supplies an absolute spelling for the parent directory.

Remaining expansions:

- Add a variant that uses a stable dirfd (for example, open `/` once) and passes a relative path containing slashes (for example `tmp/foo`), so the syscall argument has no leading `/`.
- Extend the `openat(2)` comparison to one traversal-sensitive family (`/etc/hosts` or `/var/tmp/vfs_canon_probe`) to confirm that the “symlink-component `file-read-metadata`” explanation still holds when the final open uses `openat(2)`.

Deliverable: an additional probe variant (and minimal SBPL profiles) that isolates “absolute argument string” from traversal behavior more aggressively than the current leafname-only `openat(2)` probe.

## 2) Deny-side witness channel (reliability + optional aggregation)

Per-probe observer artifacts (`out/<run_id>/observer/*.observer.json`) are now sufficient to bound several traversal-time denies, but unified-log capture can still miss a relevant deny line in tight windows.

Remaining work:

- Evaluate ingestion latency and decide whether to prefer `log stream` mode for short-lived probes, or to add an explicit post-probe delay before `log show`.
- Optionally emit a separate aggregated artifact (for example `deny_log_witnesses.json`) that joins observer lines to `(run_id, profile_id, scenario_id)` without mixing deny witnesses into FD-path witnesses.

## 3) Use `SANDBOX_CHECK_CANONICAL` as a guardrail axis (oracle lane only)

Use the existing seatbelt callout machinery to run paired oracle checks:

- “raw” vs “canonical” (`SANDBOX_CHECK_CANONICAL`) for inputs that contain:
  - a symlink component (e.g. `/tmp/...` vs `/private/tmp/...`),
  - a traversal component (`..`) in a controlled fixture path.

Interpretation constraint: treat `SANDBOX_CHECK_CANONICAL` as **reject-if-not-already-canonical** (symlink/`..` in the input), not as “canonicalize then check.” The goal is to ensure the oracle lane is interpreted correctly and can be used as a negative-control axis.

## 4) Update documentation and invariants

After each increment:

- update `Report.md` to reflect the new, decision-bounded conclusions and to keep terminology precise (resolution vs vnode spelling vs logging).
- keep “partial” vs “ok” statuses honest per family; do not upgrade without new run-scoped bundle evidence (`artifact_index.json`) and/or a promotion packet.
