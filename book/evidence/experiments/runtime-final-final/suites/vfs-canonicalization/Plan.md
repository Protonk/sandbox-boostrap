# vfs-canonicalization — Remaining experiments (Sonoma baseline)

This plan lists only the **remaining** and **expanded** experiments for `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`. The current suite already records the observed allow/deny matrix and FD path spellings described in `Report.md`; the goal here is to turn the “partial” families into decision-bounded conclusions and to strengthen the witness IR so future work does not overfit to path strings.

## 1) Explain “alias request denies even when both spellings are allowed” (`/var/tmp`, `/etc`, intermediate symlink)

Observed problem families in this suite:

- `/var/tmp/canon` is denied even under profiles that allow both `/var/tmp/canon` and `/private/var/tmp/canon`.
- `/etc/hosts` is denied even under profiles that allow both `/etc/hosts` and `/private/etc/hosts`.
- `/private/tmp/vfs_linkdir/to_var_tmp/...` is denied even under profiles that allow both the symlinked spelling and the direct `/private/var/tmp/...` spelling.

Experiment axis (goal: isolate “traversal-time authorization” vs “final-object match spelling”):

- Add profile variants that explicitly allow symlink-component traversal metadata, e.g.:
  - allow `file-read-metadata` on `/var` and `/etc` (symlink objects), plus allow `file-read*` / `file-write*` on the final target file paths.
  - allow `file-read-metadata` on `/private/tmp/vfs_linkdir/to_var_tmp` (the intermediate symlink object), plus allow `file-read*` / `file-write*` on the direct target path under `/private/var/tmp/`.
- Add probe variants that exercise the traversal surfaces explicitly:
  - `lstat` / `readlink` probes for the symlink component paths (to observe which operation/filter surface is being denied).
  - keep the existing `open(2)` probes as the “end-to-end” check.

Deliverable: a new set of SBPL profiles under `sb/` and corresponding probes in the runtime plan template such that we can say, for each family, whether the denial is explained by missing authorization on the symlink component (metadata/traversal) vs a mismatch in the effective match spelling.

## 2) Add object identity to successful-open witnesses (reduce “string-first” joins)

Add a vnode identity spine to the witness IR for successful opens:

- for every sandboxed FD that opens, record at least `(st_dev, st_ino)` from `fstat(2)`.
- record mount identity (e.g. `f_fsid`, filesystem type, and/or mount point) via `fstatfs(2)` / `statfs(2)` where feasible.

Goal: distinguish “different spellings for the same object” from “different objects that happen to share text-related spellings,” and reduce sensitivity to hardlinks, rename races, and procroot-style reconstruction differences.

Runtime support exists as an opt-in: `SANDBOX_LORE_FD_IDENTITY=1` adds optional `fd_identity` fields to scenario-lane records in `path_witnesses.json`, and is best-effort/non-fatal if the sandbox denies metadata calls post-open.

Remaining work in this suite is to run new bundles with `SANDBOX_LORE_FD_IDENTITY=1`, confirm the identity fields are populated for the allowed cases, and then re-interpret the alias/canonical joins in terms of `(st_dev, st_ino)` rather than strings.

## 3) Remove “absolute pathname string” from the caller: `openat()` / dirfd probes

Add at least one probe that opens by `(dirfd, relative_name)` rather than by an absolute path string:

- open the directory (canonical spelling) to obtain a dirfd.
- call `openat(dirfd, "relative", ...)` for the target.
- emit `F_GETPATH` / `F_GETPATH_NOFIRMLINK` for the resulting FD.

Goal: pressure-test whether the observed behavior depends on the caller supplying an absolute pathname spelling vs being driven by vnode identity and path reconstruction.

Deliverable: a new runtime helper binary (or a mode of `sandbox_reader`/`sandbox_writer`) and a small extension to the suite’s plan template and profiles.

## 4) Deny-side spelling witnesses (separate, labeled channel via unified logging)

This suite currently has strong allow-side witnesses and weaker deny-side spellings (no sandboxed FD). Add a deny-side witness channel:

- enable SBPL deny logging for a dedicated run/profile variant (e.g. `(debug deny)`), keeping it isolated from “normal” runs because it can change observability and cost.
- capture sandbox reporting via unified logging (`log stream --style json` with a stable predicate) in parallel with the run.
- correlate log events back to scenario attempts by pid and a bounded time window; store as a separate artifact (e.g. `deny_log_witnesses.json`) and never merge it into FD-path witnesses.

Goal: obtain a decision-time-ish spelling witness for denies without claiming it is the internal compare string.

Gate: do not upgrade deny-side spelling statements (especially for `/etc`, `/var/tmp`, and intermediate-symlink-in-path families) beyond “inferred/hypothesis” without this channel on this baseline.

## 5) Use `SANDBOX_CHECK_CANONICAL` as a guardrail axis (oracle lane only)

Use the existing seatbelt callout machinery to run paired oracle checks:

- “raw” vs “canonical” (`SANDBOX_CHECK_CANONICAL`) for inputs that contain:
  - a symlink component (e.g. `/tmp/...` vs `/private/tmp/...`),
  - a traversal component (`..`) in a controlled fixture path.

Interpretation constraint: treat `SANDBOX_CHECK_CANONICAL` as **reject-if-not-already-canonical** (symlink/`..` in the input), not as “canonicalize then check.” The goal is to ensure the oracle lane is interpreted correctly and can be used as a negative-control axis.

## 6) Update documentation and invariants

After each increment:

- update `Report.md` to reflect the new, decision-bounded conclusions and to keep terminology precise (resolution vs vnode spelling vs logging).
- keep “partial” vs “ok” statuses honest per family; do not upgrade without new run-scoped bundle evidence (`artifact_index.json`) and/or a promotion packet.
