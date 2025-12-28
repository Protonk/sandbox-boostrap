# VFS Canonicalization – Notes

Use this file for concise notes on commands, runs, and observations for the `/tmp` ↔ `/private/tmp` experiment.

- VFS runs now include an `apply_preflight_profile` in `plan.json` and emit a decision-stage promotion packet at `out/promotion_packet.json` when executed via the `launchd_clean` channel.
- `runtime_tools` now emits `path_witnesses.json` into the run-scoped bundle; `run_vfs.py` prefers it when building `out/runtime_results.json` (and falls back to stderr marker parsing if absent).
- Expanded path set to `/tmp/bar`, `/tmp/nested/child`, and control `/var/tmp/canon` (with canonical counterparts). `/tmp` aliases behave like `/tmp/foo` (only canonical `/private/tmp/...` literals are effective). `/var/tmp/canon` remains denied even with canonical literals present; treat as non-canonicalized/controlled alias.
- Added `file-write*` probes; writes follow the read pattern (canonical `/private/tmp/...` effective; `/var/tmp` alias denied).
- Metadata canonicalization is now handled by `book/experiments/metadata-runner/`; metadata probes removed from this suite’s matrix.
- Re-ran `python book/experiments/vfs-canonicalization/run_vfs.py` with `SANDBOX_LORE_SEATBELT_CALLOUT=1`; refreshed `out/` artifacts. Read/write patterns unchanged.
- Added variant families for `/var/tmp`, `/etc`, firmlink spelling (`/System/Volumes/Data/private/tmp`), and an intermediate symlink path; re-ran `run_vfs.py` with seatbelt callouts. `/var/tmp` and `/etc` aliases remain denied under alias-only and both profiles; firmlink spelling normalizes to `/private/tmp`; intermediate symlink path remains denied in all profiles.
- Added `F_GETPATH` emission to `sandbox_reader`/`sandbox_writer` and re-ran `run_vfs.py`. Successful `/tmp/*` and Data-volume `/System/Volumes/Data/private/tmp/*` opens report `observed_path` as `/private/tmp/*`; denied alias paths keep `observed_path` at the requested path because the FD never opens.
- `decode_tmp_profiles.json` now records normalized `literal_candidates`; compiled blobs still carry the expected literal path strings for each profile family.
- Preflight manifest already covers the new `vfs-canonicalization` SBPL sources and compiled blobs (no missing inputs for the added variants).
- Added `F_GETPATH_NOFIRMLINK` emission to `sandbox_reader`/`sandbox_writer` and re-ran `run_vfs.py`. For successful `/tmp/*` and `/System/Volumes/Data/private/*` opens, `observed_path_nofirmlink` reports the Data-volume spelling while `observed_path` reports `/private/*`.
- Added a `/var/tmp` data-spelling profile (`vfs_var_tmp_data_only`) and a third request path (`/System/Volumes/Data/private/var/tmp/...`). Canonical-only profiles allow the data spelling; the data-only profile denies all spellings; `/var/tmp` alias remains denied.
- Captured host alias inventory in `out/host_alias_inventory.json` (firmlinks list, `synthetic.conf`, and `synthetic.d` presence/contents).
- VFS expected-matrix generation now comes from the runtime_tools plan template; `run_vfs.py` uses plan-based execution and consumes run-scoped bundle outputs.
