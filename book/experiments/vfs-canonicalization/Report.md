# VFS Canonicalization – Research Report (Sonoma baseline)

## Purpose

This experiment checks how `/tmp/foo` and `/private/tmp/foo` behave structurally and at runtime on world `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`, using three simple probe profiles and a minimal runtime harness. The goal is to make one small, explicit statement about VFS canonicalization on this host: structurally, `/tmp/foo` and `/private/tmp/foo` are distinct anchors in the compiled PolicyGraph, but at runtime only the canonical `/private/tmp/...` literal is effective for enforcement.

## Setup

- **World:** `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5` (Sonoma baseline).
- **Profiles:**
  - `vfs_tmp_only` – `(deny default)` plus `allow file-read* (literal "/tmp/foo")`.
  - `vfs_private_tmp_only` – `(deny default)` plus `allow file-read* (literal "/private/tmp/foo")`.
  - `vfs_both_paths` – `(deny default)` plus both allows for `/tmp/foo` and `/private/tmp/foo`.
- **Targets:** two fixed paths:
  - `/tmp/foo`
  - `/private/tmp/foo`
- **Harness:**
  - Entry: `book/experiments/vfs-canonicalization/run_vfs.py`.
  - Structural decode via `book/api/decoder` using `book/graph/mappings/tag_layouts/tag_layouts.json`.
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
  - Anchors:
    - `/tmp/foo`:
      - `present: true`
      - `tags`: `[0, 1]`
      - `field2_values`: `[4]` (consistent with a generic name/path filter, e.g. `ipc-posix-name`/path scaffolding).
    - `/private/tmp/foo`:
      - `present: false`
      - `tags`: `[]`
      - `field2_values`: `[]`
  - Tag counts: `node_count = 30`, `tag_counts = {"4": 6, "5": 22, "1": 1, "0": 1}`.

- **Profile `vfs_private_tmp_only`**
  - Anchors:
    - `/tmp/foo`:
      - `present: true`
      - `tags`: `[0, 1]`
      - `field2_values`: `[4]`
    - `/private/tmp/foo`:
      - `present: true`
      - `tags`: `[0, 1]`
      - `field2_values`: `[4]`
  - Tag counts: identical to `vfs_tmp_only` in this cut (`node_count = 30`, same tag_counts).

- **Profile `vfs_both_paths`**
  - Anchors:
    - `/tmp/foo`:
      - `present: true`
      - `tags`: `[1]`
      - `field2_values`: `[4]`
    - `/private/tmp/foo`:
      - `present: false`
      - `tags`: `[]`
      - `field2_values`: `[]`
  - Tag counts: again `node_count = 30`, with the same aggregate tag_counts as above.

Structural takeaways:

- The decoder, under the canonical tag layouts, treats `/tmp/foo` and `/private/tmp/foo` as **distinct anchors** in the literal pool; it never collapses the two into one anchor in the compiled graph.
- For `vfs_tmp_only`, only `/tmp/foo` appears as an anchor; `/private/tmp/foo` is structurally absent.
- For `vfs_private_tmp_only`, both anchors are visible, even though the SBPL mentions only `/private/tmp/foo`, indicating that the compiled profile contains more literal structure than the source SBPL exposes directly.
- For `vfs_both_paths`, only `/tmp/foo` is attached via `literal_refs` in this cut; `/private/tmp/foo` remains structurally invisible. This suggests the decoder’s literal-binding heuristics are partial for this profile and should be interpreted cautiously.

These observations align with the broader structural story from `probe-op-structure` and `tag-layout-decode`: anchors are static graph literals, not automatically merged by the decoder when they differ by `/tmp` vs `/private/tmp`.

## Runtime observations

From `out/runtime_results.json` (via `run_vfs.py` + `run_expected_matrix` on this world):

- **Profile `vfs_tmp_only`**
  - Requested `/tmp/foo`:
    - `decision: "deny"`
    - `errno: 2`
    - `stderr: "open target: Operation not permitted\n"`
  - Requested `/private/tmp/foo`:
    - `decision: "deny"`
    - `errno: 2`
    - `stderr: "open target: Operation not permitted\n"`

- **Profile `vfs_private_tmp_only`**
  - Requested `/tmp/foo`:
    - `decision: "allow"`
    - `errno: null`
    - `stdout: "runtime-checks foo\n"`
  - Requested `/private/tmp/foo`:
    - `decision: "allow"`
    - `errno: null`
    - `stdout: "runtime-checks foo\n"`

- **Profile `vfs_both_paths`**
  - Requested `/tmp/foo`:
    - `decision: "allow"`
    - `errno: null`
    - `stdout: "runtime-checks foo\n"`
  - Requested `/private/tmp/foo`:
    - `decision: "allow"`
    - `errno: null`
    - `stdout: "runtime-checks foo\n"`

All of these runs use the same harness and shim rules as `runtime-checks` and `runtime-adversarial`; the only degrees of freedom are which profile is applied and which path the reader attempts to open.

## Interpretation

Within the scope of this experiment (file reads on this host, these profiles, and these two paths), the simplest interpretation is:

- **Effective enforcement path is `/private/tmp/foo`.**
  - A profile that mentions only `/private/tmp/foo` (`vfs_private_tmp_only`) allows both `/tmp/foo` and `/private/tmp/foo` requests, and the harness reads the same contents in both cases.
  - This is consistent with the OS canonicalizing `/tmp/foo` to `/private/tmp/foo` **before** the sandbox checks the literal.

- **A profile that mentions only `/tmp/foo` does not match after canonicalization.**
  - `vfs_tmp_only` has an evident `/tmp/foo` anchor in the decoded graph, but both `/tmp/foo` and `/private/tmp/foo` requests are denied with `EPERM` from the helper.
  - The cleanest reading is: the canonicalized path `/private/tmp/foo` is never equal to the literal `/tmp/foo` carried in this profile, so both requests fall off the allow path and are denied.

- **A profile that mentions both paths behaves like the canonical case.**
  - `vfs_both_paths` structurally attaches `/tmp/foo` and (heuristically, at least) `/private/tmp/foo`, and both requests are allowed at runtime.
  - For this world, that is indistinguishable—at the harness level—from the “canonical only” profile and serves as a control confirming that “mentioning the canonical path in SBPL” is the critical ingredient.

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
- The decoder’s literal-binding for `/private/tmp/foo` in `vfs_both_paths` is incomplete in this cut (the anchor is marked `present: false`); do not treat structural absence there as evidence that the profile lacks a canonical literal. The runtime behavior shows that the canonical path is, in fact, effective.

For a fresh agent, this experiment should be read as: **“Here is one narrow, well understood VFS behavior: on this host, `/tmp/foo` and `/private/tmp/foo` are enforced via the canonical `/private/tmp/foo` literal, and profiles that mention only `/tmp` do not match after canonicalization.”** Further VFS work (other paths, operations, and profiles) should be modeled as separate experiments that point back to this one.***
