# VFS Canonicalization – Plan (Sonoma baseline)

## Purpose and question

This experiment focuses on **VFS canonicalization across classic aliases and related path spellings** on the fixed Sonoma world (`world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`).

Core questions:

- For simple, controlled SBPL profiles, how does PolicyGraph structure and runtime behavior differ when rules mention only alias vs canonical spellings (e.g., `/tmp` vs `/private/tmp`, `/var/tmp` vs `/private/var/tmp`, `/etc` vs `/private/etc`)?
- Where do we see differences between what the SBPL “says” and what the runtime does that can be fairly attributed to VFS canonicalization (symlink or firmlink resolution), rather than to decoder bugs or policy differences?

Scope: file-read* and file-write* for:
- `/tmp/*` ↔ `/private/tmp/*` (base family, plus `/var/tmp/canon` control).
- `/var/tmp/vfs_canon_probe` ↔ `/private/var/tmp/vfs_canon_probe` (var/tmp discriminator).
- `/etc/hosts` ↔ `/private/etc/hosts` (read-only).
- `/private/tmp/vfs_firmlink_probe` ↔ `/System/Volumes/Data/private/tmp/vfs_firmlink_probe` (firmlink spelling).
- `/private/tmp/vfs_linkdir/to_var_tmp/vfs_link_probe` ↔ `/private/var/tmp/vfs_link_probe` (intermediate symlink).
Metadata canonicalization is handled by `book/experiments/metadata-runner/`.

## Relationship to existing work

Upstream inputs:

- **Tag and layout bedrock:** `book/graph/mappings/tag_layouts/tag_layouts.json` (status: ok, from `tag-layout-decode`).
- **Anchor/field2 structure:** `book/experiments/probe-op-structure/Report.md` + `out/anchor_hits.json`, plus curated anchors in `book/graph/mappings/anchors/anchor_filter_map.json` (guarded by `book/tests/planes/graph/test_anchor_filter_alignment.py`). In particular, `/tmp/foo` anchor placement and tag/field2 usage.
- **Field2 inventories:** `book/experiments/field2-filters/Report.md` with `out/field2_inventory.json` and `out/unknown_nodes.json` for high/unknown field2 values.
- **Runtime harness:** `book/api/runtime` plan execution (same shims as `runtime-checks` / `runtime-adversarial`).

Downstream use:

- Provide a small, well-documented set of structural and runtime examples for alias/canonical path families that chapters, runtime experiments, and mappings can cite when they talk about path normalization and canonicalization on this world.

## Design and probes

Profiles live under `book/experiments/vfs-canonicalization/sb/` and follow a tri-profile pattern (alias-only, canonical-only, both) per variant family:

- **Base `/tmp` family** (`vfs_tmp_only.sb`, `vfs_private_tmp_only.sb`, `vfs_both_paths.sb`):
  - `file-read*` and `file-write*` over `/tmp/*`, `/private/tmp/*`, and the `/var/tmp/canon` control pair.
- **`/var/tmp` discriminator** (`vfs_var_tmp_alias_only.sb`, `vfs_var_tmp_private_only.sb`, `vfs_var_tmp_both.sb`, `vfs_var_tmp_data_only.sb`):
  - `file-read*` and `file-write*` over `/var/tmp/vfs_canon_probe`, `/private/var/tmp/vfs_canon_probe`, and `/System/Volumes/Data/private/var/tmp/vfs_canon_probe`.
- **`/etc` read-only** (`vfs_etc_alias_only.sb`, `vfs_etc_private_only.sb`, `vfs_etc_both.sb`):
  - `file-read*` only over `/etc/hosts` ↔ `/private/etc/hosts`.
- **Firmlink spelling** (`vfs_firmlink_private_only.sb`, `vfs_firmlink_data_only.sb`, `vfs_firmlink_both.sb`):
  - `file-read*` and `file-write*` over `/private/tmp/vfs_firmlink_probe` ↔ `/System/Volumes/Data/private/tmp/vfs_firmlink_probe`.
- **Intermediate symlink** (`vfs_link_private_tmp_only.sb`, `vfs_link_var_tmp_only.sb`, `vfs_link_both.sb`):
  - `file-read*` and `file-write*` over `/private/tmp/vfs_linkdir/to_var_tmp/vfs_link_probe` ↔ `/private/var/tmp/vfs_link_probe`.

Compiled blobs are emitted under `out/<run_id>/sb_build/` by runtime plan execution (with `book.api.profile.compile_sbpl_string` as the compiler).

Scenarios:

- For each profile, attempt `file-read*` and `file-write*` on its configured alias/canonical pairs (except `/etc`, which is read-only).
- Observe:
  - Structural placement of the anchors and field2 values in the compiled graphs.
  - Runtime allow/deny behavior under an SBPL/ blob harness.

## Evidence pathway (Claim → Signals → IR)

Claims we are probing:

1. **Canonicalization claim:** For this world, certain alias/canonical pairs may resolve to the same effective path in the VFS layer; if they differ structurally or at runtime, we should be able to classify that difference as either canonicalization-only or as a true policy divergence.
2. **Structural/runtime alignment claim:** For the simple VFS profiles above, structural expectations (anchors, tags, field2) match the runtime allow/deny behavior once canonicalization is taken into account.

Signals:

- **Structural (static) signals:**
  - Decoded nodes and literal/anchor placement for the configured alias/canonical pairs in each profile:
    - tags,
    - `field2` values,
    - whether the two paths share the same structural placement or not.
  - Stored in `out/derived/decode_tmp_profiles.json` (derived from the committed bundle; includes bundle metadata).
- **Runtime signals:**
  - For each `(profile_id, requested_path)` pair:
    - decision (`allow` / `deny` / `error`) and expected decision,
    - errno (if any),
    - command output (stdout/stderr).
  - Stored in `out/derived/runtime_results.json` (derived from `out/LATEST/runtime_events.normalized.json` + `out/LATEST/path_witnesses.json`, includes bundle metadata and a `records` list).
- **Logical expectations:**
  - For each `(profile_id, requested_path)` we record an initial expectation in `out/LATEST/expected_matrix.json`, generated from the runtime plan template. The base `/tmp` family encodes the observed canonicalization pattern (including the `/var/tmp` control), while the additional variants default to a literal-only baseline so mismatches are the signal.

IR path:

- `Plan.md` (this file) encodes the question, design, and JSON shapes.
- `python -m book.api.runtime plan-build --template vfs-canonicalization --out book/experiments/vfs-canonicalization --overwrite` keeps `plan.json` and `registry/` in sync (use `--write-expected-matrix` only for a static snapshot; runtime runs emit run-scoped expected_matrix bundles).
- `python book/experiments/vfs-canonicalization/prepare_fixtures.py` prepares host fixtures under `/private/tmp` and `/private/var/tmp`.
- `python -m book.api.runtime run --plan book/experiments/vfs-canonicalization/plan.json --channel launchd_clean` emits a committed bundle under `out/<run_id>/` and updates `out/LATEST`.
- `python -m book.api.runtime emit-promotion --bundle book/experiments/vfs-canonicalization/out/LATEST --out book/experiments/vfs-canonicalization/out/promotion_packet.json --require-promotable` (when promotion is intended).
- `python book/experiments/vfs-canonicalization/derive_outputs.py --bundle book/experiments/vfs-canonicalization/out --out-dir book/experiments/vfs-canonicalization/out/derived` writes derived summaries (`runtime_results.json`, `decode_tmp_profiles.json`, `mismatch_summary.json`) that include `(run_id, artifact_index digest)` and point back to the bundle.

## JSON schema sketches

These sketches are informal; tests will check that the actual JSONs obey the same shape.

- `out/LATEST/expected_matrix.json` – object with profile-scoped probe expectations:

  ```jsonc
  {
    "world_id": "sonoma-14.4.1-23E224-arm64-dyld-2c0602c5",
    "profiles": {
      "vfs_tmp_only": {
        "blob": "book/experiments/vfs-canonicalization/out/<run_id>/runtime_profiles/vfs_tmp_only.vfs_tmp_only.runtime.sb",
        "mode": "sbpl",
        "family": "vfs_tmp",
        "semantic_group": "vfs_canonicalization",
        "probes": [
          {
            "name": "read_/tmp/foo",
            "operation": "file-read*",
            "target": "/tmp/foo",
            "expected": "deny",
            "expectation_id": "vfs_tmp_only:read_/tmp/foo"
          }
        ]
      }
    }
  }
  ```
  The generated matrix includes `file-write*` entries under each profile’s probe list.

- `out/derived/runtime_results.json` – derived bundle summary:

  ```jsonc
  {
    "schema_version": "vfs-canonicalization.runtime_summary.v0.1",
    "world_id": "sonoma-14.4.1-23E224-arm64-dyld-2c0602c5",
    "bundle": {
      "bundle_dir": "book/experiments/vfs-canonicalization/out/<run_id>",
      "run_id": "<run_id>",
      "artifact_index": "book/experiments/vfs-canonicalization/out/<run_id>/artifact_index.json",
      "artifact_index_sha256": "<sha256>"
    },
    "records": [
      {
        "profile_id": "vfs_tmp_only",
        "operation": "file-read*",
        "requested_path": "/tmp/foo",
        "actual": "deny",
        "expected": "deny",
        "observed_path": "/private/tmp/foo",
        "observed_path_source": "unsandboxed_fd_path",
        "observed_path_nofirmlink": "/System/Volumes/Data/private/tmp/foo",
        "observed_path_nofirmlink_source": "fd_path"
      }
    ]
  }
  ```

- `out/derived/decode_tmp_profiles.json` – derived structural view:

  ```jsonc
  {
    "schema_version": "vfs-canonicalization.decode_profiles.v0.1",
    "world_id": "sonoma-14.4.1-23E224-arm64-dyld-2c0602c5",
    "bundle": {
      "bundle_dir": "book/experiments/vfs-canonicalization/out/<run_id>",
      "run_id": "<run_id>",
      "artifact_index": "book/experiments/vfs-canonicalization/out/<run_id>/artifact_index.json",
      "artifact_index_sha256": "<sha256>"
    },
    "profiles": {
      "vfs_tmp_only": {
        "anchors": [
          {
            "path": "/tmp/foo",
            "present": true,
            "tags": [0],
            "field2_values": [0]
          },
          {
            "path": "/private/tmp/foo",
            "present": false,
            "tags": [],
            "field2_values": []
          }
        ],
        "literal_candidates": ["/tmp/foo", "/private/tmp/foo"],
        "node_count": 53,
        "tag_counts": {
          "4": 17,
          "5": 28
        }
      }
    }
  }
  ```

- `out/derived/mismatch_summary.json` – coarse classification (base `/tmp` family only):

  ```jsonc
  {
    "schema_version": "vfs-canonicalization.mismatch_summary.v0.1",
    "world_id": "sonoma-14.4.1-23E224-arm64-dyld-2c0602c5",
    "bundle": {
      "bundle_dir": "book/experiments/vfs-canonicalization/out/<run_id>",
      "run_id": "<run_id>",
      "artifact_index": "book/experiments/vfs-canonicalization/out/<run_id>/artifact_index.json",
      "artifact_index_sha256": "<sha256>"
    },
    "profiles": {
      "vfs_tmp_only": {
        "kind": "canonicalization",
        "note": "Profile mentions only /tmp/foo; both /tmp/foo and /private/tmp/foo are denied; interpreted as canonicalization-before-enforcement, literal /tmp/foo ineffective."
      }
    }
  }
  ```

Guardrails:

- Structural guardrail `book/integration/tests/runtime/test_vfs_canonicalization_structural.py` asserts:
  - `out/derived/decode_tmp_profiles.json` exists and includes `vfs_tmp_only`, `vfs_private_tmp_only`, `vfs_both_paths`.
  - Each profile has anchor entries for both `/tmp/foo` and `/private/tmp/foo`.
- Shape guardrail `book/integration/tests/runtime/test_vfs_canonicalization_outputs.py` asserts:
  - `out/LATEST/expected_matrix.json` and `out/derived/runtime_results.json` exist.
  - Each expected probe entry carries the required fields (`operation`, `target`, `expected`) and runtime records carry `profile_id`, `operation`, `requested_path`, `actual`, and `observed_path`.
