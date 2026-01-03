# Path Resolution, Vnode Path Spellings, and SBPL Path Filters (vfs-canonicalization)

This suite is host-bound to `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5` and measures a narrow but high-impact sandbox confounder: SBPL profiles are authored over **path spellings**, but the kernel can resolve a requested spelling to a different object spelling during name lookup, and can later reconstruct a printable path spelling for an opened FD that differs from what userland requested.

The directory name (`vfs-canonicalization`) is a local label for this suite. The measured effects are a mix of:

- **Name lookup / path resolution** (symlink traversal, firmlink-style translations, mount traversal).
- **Vnode → path spelling** (FD path reconstruction via `F_GETPATH` / `F_GETPATH_NOFIRMLINK`).

This report distinguishes what is directly witnessed (runtime bundles, path witnesses, observer logs) from what is inferred.

## How to run

Run via the runtime CLI. The authoritative outputs are the **run-scoped bundle artifacts** under `out/<run_id>/`. `out/LATEST` is a small pointer file containing the most recent committed `run_id`.

```sh
python -m book.api.runtime run \
  --plan book/evidence/experiments/runtime-final-final/suites/vfs-canonicalization/plan.json \
  --channel launchd_clean \
  --out book/evidence/experiments/runtime-final-final/suites/vfs-canonicalization/out
```

Prepare fixtures (host-local; writes under `/private/tmp` and `/private/var/tmp`):

```sh
PYTHONPATH=. python book/evidence/experiments/runtime-final-final/suites/vfs-canonicalization/prepare_fixtures.py
```

## Scope

- **World:** `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
- **Operations:** `file-read*`, `file-write*`, and a small `file-read-metadata` slice used to isolate symlink-component traversal requirements.
- **Profile pattern:** per-family tri-profiles (alias-only, canonical-only, both) plus targeted “plus metadata” variants that add only the symlink-component `file-read-metadata` allowance needed to turn a deny into an allow.
- **Path families covered:**
  - `/tmp/*` vs `/private/tmp/*` (plus control `/var/tmp/canon` vs `/private/var/tmp/canon`).
  - `/var/tmp/vfs_canon_probe` vs `/private/var/tmp/vfs_canon_probe` plus `/System/Volumes/Data/private/var/tmp/vfs_canon_probe`.
  - `/etc/hosts` vs `/private/etc/hosts` (read-only).
  - `/private/tmp/vfs_firmlink_probe` vs `/System/Volumes/Data/private/tmp/vfs_firmlink_probe`.
  - `/private/tmp/vfs_linkdir/to_var_tmp/vfs_link_probe` vs `/private/var/tmp/vfs_link_probe` (intermediate symlink-in-path).
  - `openat(2)` variants for the base `/tmp/foo` family (same profile rules; different syscall surface).

## Evidence artifacts

Run-scoped bundle artifacts:

- `out/<run_id>/artifact_index.json` (commit barrier for the bundle).
- `out/<run_id>/expected_matrix.json` (and/or `out/<run_id>/expected_matrix.generated.json`): probes per profile.
- `out/<run_id>/runtime_events.normalized.json`: normalized runtime observations (includes stage + lane).
- `out/<run_id>/path_witnesses.json`: requested path + observed FD spellings (split by lane).
- `out/<run_id>/runtime_results.json`: raw scenario results.
- `out/promotion_packet.json`: evidence interface pointing to the committed run bundle.

Derived summaries (derived from the committed bundle):

- `out/derived/runtime_results.json`: flattened summary of runtime outcomes with `observed_path_nofirmlink` when available from the sandboxed probe.
- `out/derived/decode_tmp_profiles.json`: structural decode summary (anchors, tag placement heuristics, normalized literal candidates). When the bundle does not contain `sb_build/*.sb.bin`, this script compiles the SBPL source at derive time (compile-stage only) and decodes the resulting blob bytes.
- `out/derived/mismatch_summary.json`: coarse, human-readable classification for the base `/tmp` family only.

Downstream mapping slice:

- `book/integration/carton/bundle/relationships/mappings/vfs_canonicalization/path_canonicalization_map.json`
- `book/integration/carton/bundle/relationships/mappings/vfs_canonicalization/promotion_receipt.json`

## Witness model (what these fields mean)

The suite tracks three different “path spellings” around each attempt:

- `requested_path`: the spelling passed by the probe (scenario lane) or by the baseline lane command.
- `observed_path`: a kernel-reported spelling for an opened FD via `F_GETPATH` when an FD exists.
- `observed_path_nofirmlink`: a kernel-reported spelling via `F_GETPATH_NOFIRMLINK` when the sandboxed probe opens an FD.
- optional `fd_identity`: when `SANDBOX_LORE_FD_IDENTITY=1`, the probe emits best-effort object identity for successful opens (`st_dev`, `st_ino`, and mount identity via `fstatfs(2)`). Failures are recorded as `fstat_errno` / `fstatfs_errno` and are non-fatal.

Two high-impact caveats:

- **Denied scenario attempts have no sandboxed FD.** When `out/derived/runtime_results.json` shows an `observed_path` for a denied attempt, check `observed_path_source`. `unsandboxed_fd_path` indicates a baseline-lane (unsandboxed) witness, which is diagnostic and not decision-time evidence for the denial.
- **FD spellings are diagnostic, not canonical truth.** In general, vnode→path reconstruction can be non-unique (hardlinks, multiple names) and process-relative (procroot variants). This suite does not treat `observed_path*` as “the string Seatbelt compared.”
- **Deny-side “spelling” claims require a sandbox-originated witness channel.** This suite can only witness deny-side spellings indirectly unless it captures sandbox reporting output (unified logging / observer) for the denied attempt. Without that channel, deny-side spelling statements must remain labeled as inferred/hypothesis rather than “mapped.”

## Structural decode caveat (compiled blobs and “anchor presence”)

`out/derived/decode_tmp_profiles.json` decodes `out/<run_id>/sb_build/*.sb.bin` and summarizes literal fragments and tag placement heuristics for the suite’s configured anchor paths.

The compiled format stores **literal fragments** and fragments are reused, so simple “does this path appear” heuristics can have false positives when two spellings share substrings (for example `/private/tmp/...` contains `/tmp/...`). Treat this decode output as a sanity check, not as definitive structural anchor placement.

For definitive structural anchor work, prefer the dedicated structural experiments/mappings (for example `anchor-filter-map` and `probe-op-structure`).

## Runtime results (observed allow/deny matrix)

These bullets summarize the behavior recorded in `out/derived/runtime_results.json` for this world.

- **Base `/tmp` family**
  - `vfs_tmp_only` denies `/tmp/*` and `/private/tmp/*` requests for `file-read*` and `file-write*`.
  - `vfs_private_tmp_only` allows `/tmp/*` and `/private/tmp/*` requests for `file-read*` and `file-write*`.
  - `vfs_both_paths` matches `vfs_private_tmp_only` (control).
  - In allowed `/tmp/*` requests, the sandboxed probe reports `F_GETPATH=/private/tmp/*` and (when available) `F_GETPATH_NOFIRMLINK=/System/Volumes/Data/private/tmp/*`.

- **`/var/tmp` control (in the base `/tmp` family)**
  - Even in the “both spellings” profile (`vfs_both_paths`), `/var/tmp/canon` is denied while `/private/var/tmp/canon` is allowed.

- **`/var/tmp` discriminator**
  - `vfs_var_tmp_private_only` and `vfs_var_tmp_both` allow `/private/var/tmp/vfs_canon_probe` and `/System/Volumes/Data/private/var/tmp/vfs_canon_probe` but deny `/var/tmp/vfs_canon_probe`.
  - `vfs_var_tmp_data_only` denies all three spellings, including the Data-volume spelling.

- **`/etc` read-only**
  - `vfs_etc_private_only` allows `/private/etc/hosts` but denies `/etc/hosts`.
  - `vfs_etc_both` still denies `/etc/hosts` even though it allows both `/etc/hosts` and `/private/etc/hosts` as `file-read*` literals.
  - `vfs_etc_both_plus_metadata_etc` allows `/etc/hosts` after adding only `(allow file-read-metadata (literal "/etc"))`.

- **Firmlink spelling (`/private/tmp` vs `/System/Volumes/Data/private/tmp`)**
  - `vfs_firmlink_private_only` and `vfs_firmlink_both` allow both spellings.
  - `vfs_firmlink_data_only` denies both spellings (including the Data-volume spelling).

- **Intermediate symlink-in-path**
  - `vfs_link_var_tmp_only` and `vfs_link_both` allow the direct `/private/var/tmp/vfs_link_probe` spelling but deny `/private/tmp/vfs_linkdir/to_var_tmp/vfs_link_probe`.
  - `vfs_link_private_tmp_only` denies both spellings.
  - `vfs_link_both_plus_metadata_to_var_tmp` allows the symlinked-in-path request after adding only `(allow file-read-metadata (literal "/private/tmp/vfs_linkdir/to_var_tmp"))`.

- **`openat(2)` (dirfd + relative leafname)**
  - `vfs_private_tmp_only_openat` uses the same `file-read*` rules as a “canonical-only” `/private/tmp/foo` profile, but runs paired probes using `open(2)` and `openat(2)`.
  - On this world, the `openat(2)` probes for `/tmp/foo` and `/private/tmp/foo` match the `open(2)` probes, and `fd_identity` agrees across all four (same `(st_dev, st_ino)`).

## Interpretation (careful, host-bound)

This suite supports three narrow conclusions on this world for this operation surface:

1. **For `/tmp`, the resolved spelling behaves like the effective spelling for SBPL path filters in this suite.**
   - Allowing `/private/tmp/*` is sufficient to allow sandboxed opens requested as `/tmp/*`.
   - Allowing only `/tmp/*` is not sufficient to allow sandboxed opens requested as `/tmp/*`.
   - The sandboxed probe’s `F_GETPATH=/private/tmp/*` observations are consistent with `/tmp` being resolved to `/private/tmp` during lookup, but they are not, by themselves, proof of Seatbelt’s internal compare string.

2. **For the tested families, `/System/Volumes/Data/...` spellings are not effective SBPL literals here.**
   - Profiles that allow only the Data-volume spelling still deny attempts spelled with the Data-volume path.
   - When the Data-volume spelling is allowed under a canonical `/private/...` profile, the sandboxed probe reports `F_GETPATH` in the `/private/...` namespace and `F_GETPATH_NOFIRMLINK` in the Data-volume namespace. This is evidence of multiple spellings for the same FD, not proof that Data-volume spellings are compared during enforcement.

3. **Several “alias denies even when both spellings are allowed” cases are explained by symlink-component traversal metadata.**
   - For `/etc/hosts` under `vfs_etc_both`, the deny-side observer reports `deny(1) file-read-metadata /etc`, and adding only `(allow file-read-metadata (literal "/etc"))` (profile `vfs_etc_both_plus_metadata_etc`) flips `/etc/hosts` to allow.
   - For `/var/tmp/vfs_canon_probe` under `vfs_var_tmp_both`, the deny-side observer reports `deny(1) file-read-metadata /var`, and adding only `(allow file-read-metadata (literal "/var"))` (profile `vfs_var_tmp_both_plus_metadata_var`) flips `/var/tmp/vfs_canon_probe` to allow.
   - For the intermediate symlink-in-path request under `vfs_link_both`, the deny-side observer reports `deny(1) file-read-metadata /private/tmp/vfs_linkdir/to_var_tmp`, and adding only the corresponding `file-read-metadata` literal (profile `vfs_link_both_plus_metadata_to_var_tmp`) flips the symlinked-in-path request to allow.

   These flips bound the earlier denials to a traversal-time `file-read-metadata` requirement on the symlink path component; they do not require claiming that Seatbelt compared a particular “final-object” pathname spelling on deny.

## Status and limitations

- **Status:** host-bound runtime evidence for the specific families above.
  - `/tmp` and the `/private/tmp` Data-spelling family are runtime-backed.
  - `/var/tmp`, `/etc`, and intermediate symlink-in-path denials are explained as `file-read-metadata` denials on the symlink component (bounded by plus-metadata profiles and deny-side observer lines).
- **Oracle callouts:** when `SANDBOX_LORE_SEATBELT_CALLOUT=1` is used, interpret `SANDBOX_CHECK_CANONICAL` as a **reject-if-not-already-canonical** flag (symlink/`..` in the input), not as “canonicalize then check.” Do not treat callout output as a path discovery mechanism.

See `Plan.md` for the remaining experiments intended to turn the “partial” families into decision-bounded conclusions on this baseline.
