# VFS Canonicalization – Research Report

This experiment checks how alias/canonical path families behave structurally and at runtime on world `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`, using tri-profile variants (alias-only, canonical-only, both) plus a data-spelling-only variant for `/var/tmp`, and a minimal runtime harness that exercises file-read* and file-write*. It covers `/tmp` ↔ `/private/tmp`, a `/var/tmp` discriminator (including `/System/Volumes/Data/private/var/tmp`), `/etc` read-only, a firmlink spelling for `/private/tmp`, and an intermediate symlink-in-path probe. The goal is to bound canonicalization behavior for these path families on this host: structurally, alias and canonical spellings are distinct anchors in the compiled PolicyGraph, while runtime behavior shows where canonicalization does (and does not) make those literals effective.

## Setup

- **World:** `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5` (Sonoma baseline).
- **Profiles:** tri-profile variants per family (alias-only, canonical-only, both), plus a data-spelling-only variant for `/var/tmp`. Families covered:
  - `/tmp/*` ↔ `/private/tmp/*` (base family, plus `/var/tmp/canon` control).
  - `/var/tmp/vfs_canon_probe` ↔ `/private/var/tmp/vfs_canon_probe` plus `/System/Volumes/Data/private/var/tmp/vfs_canon_probe` (var/tmp discriminator + data spelling).
  - `/etc/hosts` ↔ `/private/etc/hosts` (read-only).
  - `/private/tmp/vfs_firmlink_probe` ↔ `/System/Volumes/Data/private/tmp/vfs_firmlink_probe` (firmlink spelling).
  - `/private/tmp/vfs_linkdir/to_var_tmp/vfs_link_probe` ↔ `/private/var/tmp/vfs_link_probe` (intermediate symlink).
- **Targets:** the path pairs above; each family is tested only against its own configured pair(s).
- **Harness:**
  - Entry: `book/experiments/vfs-canonicalization/run_vfs.py`.
  - Plan-data generated via `python -m book.api.runtime plan-build --template vfs-canonicalization --out book/experiments/vfs-canonicalization --overwrite`.
  - Runtime harness via `book.api.runtime` plan execution, reusing the same shims as `runtime-checks` / `runtime-adversarial`.
  - Structural decode via `book/api/profile_tools/decoder.py` using `book/graph/mappings/tag_layouts/tag_layouts.json`.
- **Outputs:**
  - `plan.json` + `registry/{probes,profiles}.json` – plan/registry data generated from the runtime template.
  - `out/expected_matrix.json` – human expectations for `(profile_id, requested_path, expected_decision)` (template-derived).
  - `out/<run_id>/expected_matrix.json` – runtime expected matrix (plan-derived, harness-ready).
  - `out/<run_id>/runtime_results.json` – raw runtime harness results (per-profile dict form).
  - `out/<run_id>/runtime_events.normalized.json` – normalized runtime observations (per scenario).
  - `out/promotion_packet.json` – promotion packet (preferred evidence interface) pointing to the committed run-scoped bundle.
  - `out/runtime_results.json` – simplified array of runtime observations (per scenario).
  - `out/decode_tmp_profiles.json` – structural view of anchors/tags/field2 (plus literal candidates) for all configured path pairs in each profile.
  - `out/mismatch_summary.json` – coarse classification for the base `/tmp` family (canonicalization vs control).
  - `out/host_alias_inventory.json` – host-local firmlinks and synthetic root config snapshots (presence + contents).
  - `book/graph/mappings/vfs_canonicalization/path_canonicalization_map.json` – generated mapping slice derived from the promotion packet, with `book/graph/mappings/vfs_canonicalization/promotion_receipt.json` as the audit receipt.
- **Observed vs canonicalized paths:**
  - The harness now emits `F_GETPATH` and (when available) `F_GETPATH_NOFIRMLINK` for successful opens. `observed_path` is sourced from `F_GETPATH` when present, and `observed_path_nofirmlink` captures the alternate FD path spelling when available.
  - For denied requests the FD never opens, so neither FD path exists; `observed_path` remains the requested path and canonicalization for denied paths is inferred from behavior.
- **Host alias inventory:** `out/host_alias_inventory.json` captures `/usr/share/firmlinks`, `/etc/synthetic.conf`, and `/etc/synthetic.d` on this host. The firmlinks list exists but does not include `/private`; `synthetic.conf` and `synthetic.d` are absent. Treat this as a host-specific bound, not a general rule.

## Structural observations

From `out/decode_tmp_profiles.json` (anchors, tags, field2, and normalized literal candidates):

- **Profile `vfs_tmp_only`**
  - Anchors present for `/tmp/foo`, `/tmp/bar`, `/tmp/nested/child`, `/var/tmp/canon`; canonical counterparts absent. Tag counts: `node_count = 53`, `tag_counts = {"4": 17, "5": 28, "3": 4, "1": 1, "0": 3}`.

- **Profile `vfs_private_tmp_only`**
  - Anchors present for canonical `/private/tmp/*`, `/private/var/tmp/canon` and (via decoder literals) the `/tmp/*` aliases. Tag counts: `node_count = 52`, `tag_counts = {"4": 17, "5": 28, "3": 4, "1": 1, "0": 2}`.

- **Profile `vfs_both_paths`**
  - Anchors present for both alias and canonical forms across the path set; tag counts match `vfs_tmp_only` (`node_count = 53`, `tag_counts = {"4": 17, "5": 28, "3": 4, "1": 1, "0": 3}`).

Structural takeaways:

- The decoder, under the canonical tag layouts, treats `/tmp/*` and `/private/tmp/*` as **distinct anchors** in the literal pool; it never collapses alias/canonical pairs into one anchor in the compiled graph.
- For `vfs_tmp_only`, only alias anchors appear; canonical `/private/...` anchors are structurally absent.
- For `vfs_private_tmp_only`, canonical anchors are present; decoder also surfaces the alias `/tmp/...` anchors via normalized literal fragments.
- For `vfs_both_paths`, alias and canonical anchors are present across the path set, matching the SBPL intent.
- The same pattern holds across the added variants: alias-only profiles contain only their alias anchor (e.g., `/var/tmp/vfs_canon_probe`, `/etc/hosts`, `/private/tmp/vfs_linkdir/...`), canonical-only profiles contain only their canonical anchor, and the decoder does not collapse firmlink spellings into a single literal.
- The `literal_candidates` lists include the expected full paths for each profile (plus type-byte-trimmed fragments); this confirms the compiled blobs carry the literal strings from SBPL rather than `subpath` filters for these probes (heuristic normalization only).

These observations align with the broader structural story from `probe-op-structure` and `tag-layout-decode`: anchors are static graph literals, not automatically merged by the decoder when they differ by alias/canonical spellings.

## Runtime observations

From `out/runtime_results.json` (via `run_vfs.py` + runtime plan execution on this world):

- **Base `/tmp` family**
  - `vfs_tmp_only` denies all alias and canonical requests across the path set for file-read* and file-write*.
  - `vfs_private_tmp_only` allows all `/tmp/*` and `/private/tmp/*` requests (alias or canonical) but denies `/var/tmp/canon`; allows `/private/var/tmp/canon`. Successful `/tmp/*` requests report `observed_path` as `/private/tmp/*` via `F_GETPATH`.
  - `vfs_both_paths` matches `vfs_private_tmp_only`: all `/tmp/*` + `/private/tmp/*` allowed; `/var/tmp/canon` denied; `/private/var/tmp/canon` allowed.
- **`/var/tmp` discriminator**
  - `vfs_var_tmp_alias_only` denies both `/var/tmp/vfs_canon_probe` and `/private/var/tmp/vfs_canon_probe`.
  - `vfs_var_tmp_private_only` allows `/private/var/tmp/vfs_canon_probe` and `/System/Volumes/Data/private/var/tmp/vfs_canon_probe` but denies `/var/tmp/vfs_canon_probe`; the data spelling request yields `F_GETPATH=/private/var/tmp/...` and `F_GETPATH_NOFIRMLINK=/System/Volumes/Data/private/var/tmp/...`.
  - `vfs_var_tmp_both` matches `vfs_var_tmp_private_only`: allows canonical + data spelling, still denies `/var/tmp/vfs_canon_probe`.
  - `vfs_var_tmp_data_only` denies all three spellings; data spelling requests never open, so `observed_path` stays at the requested path.
- **`/etc` read-only**
  - `vfs_etc_alias_only` denies both `/etc/hosts` and `/private/etc/hosts`.
  - `vfs_etc_private_only` allows `/private/etc/hosts` but denies `/etc/hosts`.
  - `vfs_etc_both` allows `/private/etc/hosts` but still denies `/etc/hosts`; alias requests never open, so `F_GETPATH` is unavailable there.
- **Firmlink spelling (`/private/tmp` vs `/System/Volumes/Data/private/tmp`)**
  - `vfs_firmlink_private_only` allows both spellings; when requesting the Data spelling, `F_GETPATH` reports `/private/tmp/...` and `F_GETPATH_NOFIRMLINK` reports `/System/Volumes/Data/private/tmp/...`.
  - `vfs_firmlink_data_only` denies both spellings.
  - `vfs_firmlink_both` allows both spellings.
- **Intermediate symlink path**
  - `vfs_link_private_tmp_only` denies both the symlinked-in-path form and the direct `/private/var/tmp` path.
  - `vfs_link_var_tmp_only` allows only the direct `/private/var/tmp` path; the symlinked-in-path request is denied.
  - `vfs_link_both` allows only the direct `/private/var/tmp` path; the symlinked-in-path request is still denied (no `F_GETPATH` for the denied path).

All of these runs use the same harness and shim rules as `runtime-checks` and `runtime-adversarial`; the only degrees of freedom are which profile is applied and which path the reader attempts to open.

## Interpretation

Within the scope of this experiment (file reads/writes on this host, these profiles, and these paths), the simplest interpretation is:

- **Effective enforcement path is `/private/tmp/...` for the `/tmp` path set.**
  - A profile that mentions only canonical `/private/tmp/*` paths (`vfs_private_tmp_only`) allows both `/tmp/*` and `/private/tmp/*` requests, and the harness reads the same contents in both cases.
  - `F_GETPATH` on successful `/tmp/*` opens reports `/private/tmp/*`, which is a direct witness that the FD resolves to the canonical path before policy evaluation (partial only for allowed cases).
  - `F_GETPATH_NOFIRMLINK` reports `/System/Volumes/Data/private/tmp/*` for the same opens, so `F_GETPATH` is a firmlink-normalized rendering, not a proof of the literal Seatbelt matched on its own.

- **A profile that mentions only `/tmp/*` does not match after canonicalization.**
  - `vfs_tmp_only` has evident `/tmp/*` anchors in the decoded graph, but both `/tmp/*` and `/private/tmp/*` requests are denied with `EPERM` from the helper.
  - The cleanest reading is: the canonicalized path `/private/tmp/*` is never equal to the `/tmp/*` literal carried in this profile, so requests fall off the allow path and are denied.

- **A profile that mentions both paths behaves like the canonical case.**
  - `vfs_both_paths` structurally attaches both `/tmp/*` and `/private/tmp/*`, and both requests are allowed at runtime.
  - For this world, that is indistinguishable—at the harness level—from the “canonical only” profile and serves as a control confirming that “mentioning the canonical path in SBPL” is the critical ingredient.

- **`/var/tmp` and `/etc` behave differently from `/tmp`.**
  - For both `/var/tmp/vfs_canon_probe` and `/etc/hosts`, alias-only profiles deny both forms, and canonical-only profiles allow only the canonical `/private/...` form; even the both-paths profiles do not allow the alias form.
  - Adding the Data-volume spelling to the `/var/tmp` matrix shows that `/System/Volumes/Data/private/var/tmp/...` is allowed when canonical `/private/var/tmp/...` is allowed, and denied when only the Data spelling is allowed. This points to matching on `/private/var/tmp/...` rather than a third spelling, but alias `/var/tmp/...` remains **partial**.

- **Firmlink spelling is normalized to `/private/tmp` in this suite.**
  - The Data-volume spelling (`/System/Volumes/Data/private/tmp/...`) is allowed when `/private/tmp/...` is allowed, and is denied when only the Data spelling is allowed.
  - For successful opens of the Data spelling, `F_GETPATH` returns `/private/tmp/...` while `F_GETPATH_NOFIRMLINK` returns the Data spelling; the allow/deny matrix still aligns with the canonical `/private/tmp/...` literal, so this remains **partial**, single path family.

- **Data spelling collapse is both a rendering choice and a match boundary here.**
  - `F_GETPATH` normalizes Data spellings to `/private/...` while `F_GETPATH_NOFIRMLINK` preserves the Data spelling, so the FD-path witness alone is a rendering signal.
  - The allow/deny matrix for `/var/tmp` shows that a profile allowing only the Data spelling still denies the Data spelling, while a profile allowing `/private/var/tmp/...` allows it. That points to Seatbelt matching on the canonical `/private/...` spelling for this family on this host (still partial for `/var/tmp` alias requests).

- **Intermediate symlink paths do not match either literal.**
  - Requests via `/private/tmp/vfs_linkdir/to_var_tmp/...` are denied even when the profile explicitly allows that literal or allows the canonical `/private/var/tmp/...` path.
  - This indicates that intermediate symlink resolution is **not** behaving like a simple realpath-style rewrite for policy matching here; the exact match string remains **under exploration**.

- **Operation coverage (writes).**
  - `file-write*` mirrors `file-read*` across the variants in this suite.
  - Metadata canonicalization is covered by `book/experiments/metadata-runner/Report.md` and is out of scope for this experiment.

In other words:

- **Structure:** the decoder sees alias/canonical pairs as separate anchors across the configured families; nothing in the compiled PolicyGraph collapses them.
- **Runtime:** for `/tmp/*`, the effective literal is `/private/tmp/*`; for the Data-volume spelling of `/private/tmp`, matching still follows the `/private/tmp/*` literal; for `/var/tmp` and `/etc`, alias forms remain denied in this suite; intermediate symlink paths remain unresolved.

This is a narrow, host-specific VFS story: for **read/write semantics in this suite** on this Sonoma world, “the sandbox literal that matters is `/private/tmp/*`, not `/tmp/*`,” while `/var/tmp`, `/etc`, and intermediate symlink paths remain **partial/under exploration**.

## Status and limitations

- **Tier:** **mapped (structural + runtime)** for the specific scenario covered here.
  - Base `/tmp` canonicalization and the firmlink spelling results are runtime-backed; `/var/tmp`, `/etc`, and intermediate symlink outcomes remain **partial/under exploration**.

Scope and constraints:

- World: `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5` only.
- Operations: `file-read*` and `file-write*` via the existing runtime harness (plus `/etc/hosts` read-only).
- Paths: base `/tmp/*` and `/private/tmp/*` set, `/var/tmp/canon` control, `/var/tmp/vfs_canon_probe`, `/etc/hosts`, `/System/Volumes/Data/private/tmp/vfs_firmlink_probe`, and the intermediate symlink path under `/private/tmp/vfs_linkdir/`.
- Logging: the harness captures `F_GETPATH` and `F_GETPATH_NOFIRMLINK` for successful opens; `observed_path` is the firmlink-normalized FD path, and `observed_path_nofirmlink` records the alternate spelling when available. Denied paths still lack FD paths and remain inference-only.

Non-claims and cautions:

- This experiment does **not** attempt to generalize to all alias families; `/var/tmp`, `/etc`, and intermediate symlink behavior remain **partial** and may involve additional alias spellings not yet probed.
- It does not alter or override the structural anchor story from `probe-op-structure` or the field2 inventories from `field2-filters`; it only adds small, concrete runtime stories on top of them for these path families.
- Literal decoding here strips the leading literal-type byte; earlier substring-based checks could misclassify which anchors were present. Treat any future deviations as decoder hygiene issues, not policy changes.
- The latest runtime harness run (captured in `out/runtime_results.json`) enabled seatbelt callouts for file-read* and file-write* probes; the underlying world and profiles are otherwise unchanged.

Why expand canonicalization scope? Canonicalization determines which literals are actually enforceable on this host. If `/tmp` → `/private/tmp` is just one case in a broader VFS normalization layer, knowing where else literals are rewritten keeps profile interpretation honest (PolicyGraph literals vs runtime matches), strengthens runtime evidence beyond a single fixture, and gives chapters/experiments a reusable runtime invariant (or a bounded brittleness) instead of overfitting to one anchor that might never match. In short, broader probing tells the textbook which literal strings are semantically live on Sonoma.

What further probes would tell us (high-level expectations):
- Whether `/tmp` → `/private/tmp` applies uniformly across subpaths or only to select fixtures, refining which literals the kernel truly checks.
- How tolerant literal matching is to common path variants (nested dirs, sibling files, extra slashes), revealing the practical forgiveness/strictness of the normalization layer.
- Whether `/var/tmp` and `/etc` alias forms are being rewritten to a different canonical spelling (for example, Data-volume paths) before policy evaluation.
- Whether canonicalization sits in front of other ops (metadata) as well as reads/writes, clarifying the enforcement stack per operation; op-specific differences would explain why profiles that “work” for reads could still fail for metadata.
- The limits: cases that do not canonicalize anchor the story and prevent overgeneralization.
- A richer set of runtime-backed invariants (or bounded partial/brittle cases) that chapters and other experiments can safely cite.

For a fresh agent, this experiment should be read as: **“Here is one narrow, well understood VFS behavior: on this host, the `/tmp` alias paths in this suite are enforced via the canonical `/private/tmp/*` literals, and profiles that mention only `/tmp` do not match after canonicalization; firmlink spellings of `/private/tmp` normalize back to `/private/tmp` in this suite; `/var/tmp`, `/etc`, and intermediate symlink paths remain partial.”** Further VFS work (other paths, operations, and profiles) should be modeled as separate experiments that point back to this one.
