# VFS Canonicalization – Notes

Use this file for concise notes on commands, runs, and observations for the `/tmp` ↔ `/private/tmp` experiment.

- Re-running the runtime harness with `sandbox_reader` on this host now returns `sandbox_init` `EPERM` during apply. Kept the canonicalization runtime outputs from the last successful run; revisit sandbox_apply gating if a fresh run is needed.
- Latest runtime rerun succeeded only after enabling the Codex harness `--yolo` flag (more permissive environment) to bypass the sandbox_apply gate; outputs now reflect that run.
- Expanded path set to `/tmp/bar`, `/tmp/nested/child`, and control `/var/tmp/canon` (with canonical counterparts). `/tmp` aliases behave like `/tmp/foo` (only canonical `/private/tmp/...` literals are effective). `/var/tmp/canon` remains denied even with canonical literals present; treat as non-canonicalized/controlled alias.
- Added `file-write*` probes; writes follow the read pattern (canonical `/private/tmp/...` effective; `/var/tmp` alias denied).
- Metadata canonicalization is now handled by `book/experiments/metadata-runner/`; metadata probes removed from this suite’s matrix.
- Re-ran `python book/experiments/vfs-canonicalization/run_vfs.py` with `SANDBOX_LORE_SEATBELT_CALLOUT=1`; refreshed `out/` artifacts. Read/write patterns unchanged.
- Added variant families for `/var/tmp`, `/etc`, firmlink spelling (`/System/Volumes/Data/private/tmp`), and an intermediate symlink path; re-ran `run_vfs.py` with seatbelt callouts. `/var/tmp` and `/etc` aliases remain denied under alias-only and both profiles; firmlink spelling normalizes to `/private/tmp`; intermediate symlink path remains denied in all profiles.
