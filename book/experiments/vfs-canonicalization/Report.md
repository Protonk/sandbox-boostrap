# VFS Canonicalization – Research Report (Sonoma baseline)

## Purpose

TBD – Fill once the first structural + runtime runs have been completed. This section will restate, in substrate vocabulary, the questions about `/tmp` ↔ `/private/tmp` path behavior on this Sonoma world and summarize how this experiment answers them.

## Setup

- World and baseline.
- Profiles (`vfs_tmp_only`, `vfs_private_tmp_only`, `vfs_both_paths`).
- Harness (`run_vfs.py` using `book.api.runtime_harness.runner.run_expected_matrix` and `book/api/decoder`).
- Inputs/outputs (`sb/`, `sb/build/`, `out/expected_matrix.json`, `out/runtime_results.json`, `out/decode_tmp_profiles.json`).

## Structural observations

TBD – After decoding the VFS profiles:

- Per profile, describe where `/tmp/foo` and `/private/tmp/foo` show up in tags/anchors/field2.
- Note whether the two paths share the same structural placement or differ.

## Runtime observations

TBD – After running the runtime harness:

- Per `(profile_id, requested_path)`, record decision/errno and any observed path details that are visible at this layer.
- Call out any consistent differences between `/tmp` and `/private/tmp`.

## Interpretation

TBD – Once structural + runtime slices have been collected:

- Classify observed differences as:
  - canonicalization-only (same effective policy, different strings), or
  - true divergences (structural/runtime differences not attributable to `/tmp` ↔ `/private/tmp` normalization).

## Status and limitations

TBD – For the first cut, mark the experiment status (likely **mapped-but-partial, structural + runtime**) and list:

- Exact operations and paths covered.
- Known limitations (no symlinks, no other VFS quirks, observed_path may just be the requested path if deeper logging is unavailable).
- Pointers to upstream experiments (probe-op-structure, field2-filters) and to any guardrail tests added for this suite.
