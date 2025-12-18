# VFS Canonicalization – Research Report

This experiment checks how `/tmp/foo` and `/private/tmp/foo` behave structurally and at runtime on world `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`, using three simple probe profiles and a minimal runtime harness. The goal is to make one small, explicit statement about VFS canonicalization on this host: structurally, `/tmp/foo` and `/private/tmp/foo` are distinct anchors in the compiled PolicyGraph, but at runtime only the canonical `/private/tmp/...` literal is effective for enforcement.

## Setup

- **World:** `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5` (Sonoma baseline).
- **Profiles:**
  - `vfs_tmp_only` – `(deny default)` plus `allow file-read* (literal "/tmp/foo")`.
  - `vfs_private_tmp_only` – `(deny default)` plus `allow file-read* (literal "/private/tmp/foo")`.
  - `vfs_both_paths` – `(deny default)` plus both allows for `/tmp/foo` and `/private/tmp/foo`.
- **Targets:** four path pairs:
  - `/tmp/foo` ↔ `/private/tmp/foo`
  - `/tmp/bar` ↔ `/private/tmp/bar`
  - `/tmp/nested/child` ↔ `/private/tmp/nested/child`
  - `/var/tmp/canon` ↔ `/private/var/tmp/canon` (control outside `/tmp`)
- **Harness:**
  - Entry: `book/experiments/vfs-canonicalization/run_vfs.py`.
  - Structural decode via `book/api/profile_tools/decoder.py` using `book/graph/mappings/tag_layouts/tag_layouts.json`.
  - Runtime harness via `book.api.runtime_harness.runner.run_expected_matrix`, reusing the same shims as `runtime-checks` / `runtime-adversarial`.
- **Outputs:**
  - `sb/build/*.sb.bin` – compiled VFS profiles.
  - `out/expected_matrix.json` – human expectations for `(profile_id, requested_path, expected_decision)`.
  - `out/expected_matrix_harness.json` – harness-compatible expected matrix (internal).
  - `out/harness/runtime_results.json` – raw runtime harness results (per-profile dict form).
  - `out/runtime_results.json` – simplified array of runtime observations (per scenario).
  - `out/decode_tmp_profiles.json` – structural view of anchors/tags/field2 for `/tmp/foo` and `/private/tmp/foo` in each profile.
  - `out/mismatch_summary.json` – coarse classification of each profile’s behavior as canonicalization vs control.
- **Observed vs canonicalized paths:**
  - At this layer the harness does **not** expose the kernel’s canonical path; `observed_path` in `runtime_results.json` is set equal to `requested_path`. Canonicalization is inferred from behavior (which profiles allow which requests), not from string differences.

## Structural observations

From `out/decode_tmp_profiles.json`:

- **Profile `vfs_tmp_only`**
  - Anchors present for `/tmp/foo`, `/tmp/bar`, `/tmp/nested/child`, `/var/tmp/canon`; canonical counterparts absent. Tag counts: `node_count = 30`, `tag_counts = {"4": 6, "5": 22, "1": 1, "0": 1}`.

- **Profile `vfs_private_tmp_only`**
  - Anchors present for canonical `/private/tmp/*`, `/private/var/tmp/canon` and (via decoder literals) the `/tmp/*` aliases; tag counts identical to `vfs_tmp_only`.

- **Profile `vfs_both_paths`**
  - Anchors present for both alias and canonical forms across the path set; tag counts: `node_count = 31`, `tag_counts = {"4": 6, "5": 23, "1": 1, "0": 1}`.

Structural takeaways:

- The decoder, under the canonical tag layouts, treats `/tmp/foo` and `/private/tmp/foo` as **distinct anchors** in the literal pool; it never collapses the two into one anchor in the compiled graph.
- For `vfs_tmp_only`, only alias anchors appear; canonical `/private/...` anchors are structurally absent.
- For `vfs_private_tmp_only`, canonical anchors are present; decoder also surfaces the alias `/tmp/...` anchors via normalized literal fragments.
- For `vfs_both_paths`, alias and canonical anchors are present across the path set, matching the SBPL intent.

These observations align with the broader structural story from `probe-op-structure` and `tag-layout-decode`: anchors are static graph literals, not automatically merged by the decoder when they differ by `/tmp` vs `/private/tmp`.

## Runtime observations

From `out/runtime_results.json` (via `run_vfs.py` + `run_expected_matrix` on this world):

- **Profile `vfs_tmp_only`** – denies all alias and canonical requests across the path set (expected under canonicalization-before-enforcement).
- **Profile `vfs_private_tmp_only`** – allows all `/tmp/*` and `/private/tmp/*` requests (alias or canonical) but denies `/var/tmp/canon`; allows `/private/var/tmp/canon`.
- **Profile `vfs_both_paths`** – same pattern as above: allows all `/tmp/*` and `/private/tmp/*` requests; denies `/var/tmp/canon`; allows `/private/var/tmp/canon`.

All of these runs use the same harness and shim rules as `runtime-checks` and `runtime-adversarial`; the only degrees of freedom are which profile is applied and which path the reader attempts to open.

## Interpretation

Within the scope of this experiment (file reads on this host, these profiles, and these paths), the simplest interpretation is:

- **Effective enforcement path is `/private/tmp/foo`.**
  - A profile that mentions only `/private/tmp/foo` (`vfs_private_tmp_only`) allows both `/tmp/foo` and `/private/tmp/foo` requests, and the harness reads the same contents in both cases.
  - This is consistent with the OS canonicalizing `/tmp/foo` to `/private/tmp/foo` **before** the sandbox checks the literal.

- **A profile that mentions only `/tmp/foo` does not match after canonicalization.**
  - `vfs_tmp_only` has an evident `/tmp/foo` anchor in the decoded graph, but both `/tmp/foo` and `/private/tmp/foo` requests are denied with `EPERM` from the helper.
  - The cleanest reading is: the canonicalized path `/private/tmp/foo` is never equal to the literal `/tmp/foo` carried in this profile, so both requests fall off the allow path and are denied.

- **A profile that mentions both paths behaves like the canonical case.**
  - `vfs_both_paths` structurally attaches both `/tmp/foo` and `/private/tmp/foo`, and both requests are allowed at runtime.
  - For this world, that is indistinguishable—at the harness level—from the “canonical only” profile and serves as a control confirming that “mentioning the canonical path in SBPL” is the critical ingredient.

- **/var/tmp control diverges.**
  - Requests to `/var/tmp/canon` are denied even when the canonical `/private/var/tmp/canon` literal is present; the canonical path itself is allowed. On this host and harness, `/var/tmp` does not behave like the `/tmp` ↔ `/private/tmp` pair; treat this as a non-canonicalized or separately-gated alias.
- **Operation coverage (writes/metadata).**
  - `file-write*` follows the same pattern as reads: `/tmp` aliases canonicalize to `/private/tmp` and are allowed when the canonical literal is present; `/var/tmp/canon` stays denied.
  - `file-read-metadata` / `file-write-metadata` probes return `deny` with empty stderr and exit_code `-6` even on canonical paths; treat these as **blocked/partial** due to harness limitations (runner lacks metadata op coverage), not as evidence that metadata ops refuse canonicalized paths.

In other words:

- **Structure:** the decoder sees `/tmp/foo` and `/private/tmp/foo` as separate anchors; nothing in the compiled PolicyGraph collapses them.
- **Runtime:** the kernel (or a lower VFS layer) canonicalizes `/tmp/foo` to `/private/tmp/foo` before the sandbox’s literal match, so a literal on `/private/tmp/foo` is effective for both paths, while a literal on `/tmp/foo` is not.

This is a narrow, host-specific VFS story: for **read semantics on `/tmp/foo`** on this Sonoma world, “the sandbox literal that matters is `/private/tmp/foo`, not `/tmp/foo`.”

## Status and limitations

- **Status:** **mapped-but-partial (structural + runtime)** for the specific scenario covered here.

Scope and constraints:

- World: `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5` only.
- Operations: `file-read*` with the existing runtime harness; no writes, metadata ops, or other VFS behaviors.
- Paths: only `/tmp/foo` and `/private/tmp/foo`, with the concrete fixtures created by `run_vfs.py`.
- Logging: the harness does **not** surface canonicalized path strings; `observed_path` equals `requested_path` in `runtime_results.json`. Canonicalization is inferred via behavior patterns (allow/deny) under controlled profiles, not via direct path logging.

Non-claims and cautions:

- This experiment does **not** attempt to generalize to all `/tmp` paths or to other VFS quirks (symlinks, other aliases, different directories under `/tmp`).
- It does not alter or override the structural anchor story from `probe-op-structure` or the field2 inventories from `field2-filters`; it only adds a small, concrete runtime story on top of them for these two paths.
- Literal decoding here strips the leading literal-type byte; earlier substring-based checks could misclassify which anchors were present. Treat any future deviations as decoder hygiene issues, not policy changes.
- The latest runtime harness run (captured in `out/runtime_results.json`) was executed after enabling the more permissive Codex harness mode via the `--yolo` flag, which cleared the prior sandbox_apply gate; the underlying world and profiles are otherwise unchanged.

Why expand canonicalization scope? Canonicalization determines which literals are actually enforceable on this host. If `/tmp` → `/private/tmp` is just one case in a broader VFS normalization layer, knowing where else literals are rewritten keeps profile interpretation honest (PolicyGraph literals vs runtime matches), strengthens runtime evidence beyond a single fixture, and gives chapters/experiments a reusable runtime invariant (or a bounded brittleness) instead of overfitting to one anchor that might never match. In short, broader probing tells the textbook which literal strings are semantically live on Sonoma.

What further probes would tell us (high-level expectations):
- Whether `/tmp` → `/private/tmp` applies uniformly across subpaths or only to select fixtures, refining which literals the kernel truly checks.
- How tolerant literal matching is to common path variants (nested dirs, sibling files, extra slashes), revealing the practical forgiveness/strictness of the normalization layer.
- Whether canonicalization sits in front of other ops (write, metadata) as well as reads, clarifying the enforcement stack per operation; op-specific differences would explain why profiles that “work” for reads could still fail for writes/metadata.
- The limits: cases that do not canonicalize anchor the story and prevent overgeneralization.
- A richer set of runtime-backed invariants (or bounded partial/brittle cases) that chapters and other experiments can safely cite.

For a fresh agent, this experiment should be read as: **“Here is one narrow, well understood VFS behavior: on this host, `/tmp/foo` and `/private/tmp/foo` are enforced via the canonical `/private/tmp/foo` literal, and profiles that mention only `/tmp` do not match after canonicalization.”** Further VFS work (other paths, operations, and profiles) should be modeled as separate experiments that point back to this one.***
