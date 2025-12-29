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
- **Anchor/field2 structure:** `book/experiments/probe-op-structure/Report.md` + `out/anchor_hits.json`, plus curated anchors in `book/graph/mappings/anchors/anchor_filter_map.json` (guarded by `book/tests/test_anchor_filter_alignment.py`). In particular, `/tmp/foo` anchor placement and tag/field2 usage.
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
  - Stored in `out/decode_tmp_profiles.json`.
- **Runtime signals:**
  - For each `(profile_id, requested_path)` pair:
    - decision (`allow` / `deny` / `error`),
    - errno (if any),
    - command output (stdout/stderr).
  - Stored in `out/runtime_results.json` (simple array form) with `profile_id`, `operation`, `requested_path`, `observed_path`, `observed_path_source`, `observed_path_nofirmlink`, `observed_path_nofirmlink_source`, `observed_path_nofirmlink_errno` (when available), `decision`, `errno`, `raw_log`.
- **Logical expectations:**
  - For each `(profile_id, requested_path)` we record an initial expectation in `out/expected_matrix.json`, generated from the runtime plan template. The base `/tmp` family encodes the observed canonicalization pattern (including the `/var/tmp` control), while the additional variants default to a literal-only baseline so mismatches are the signal.

IR path:

- `Plan.md` (this file) encodes the question, design, and JSON shapes.
- `run_vfs.py` (harness script) will:
  - expects plan/registry data generated via the runtime plan template (and keeps `out/expected_matrix.json` in sync via `plan-build`),
  - execute the runtime plan into a run-scoped bundle under `out/<run_id>/`,
  - emit `out/promotion_packet.json` pointing at the committed run-scoped bundle (preferred evidence interface for downstream mappings/consumers),
  - down-convert the harness runtime results into `out/runtime_results.json` (authoritative runtime behavior for this suite on this world),
  - emit `out/decode_tmp_profiles.json` via `book/api/profile/decoder/` (structural view, using blobs from `out/<run_id>/sb_build`),
  - emit a small `out/mismatch_summary.json` that classifies each profile’s behavior (“canonicalization” vs “control”) for downstream readers.

## JSON schema sketches

These sketches are informal; tests will check that the actual JSONs obey the same shape.

- `out/expected_matrix.json` – array of entries:

  ```jsonc
  [
    {
      "profile_id": "vfs_tmp_only",
      "operation": "file-read*",
      "requested_path": "/tmp/foo",
      "expected_decision": "deny",
      "notes": "canonicalization makes /tmp literal ineffective"
    },
    {
      "profile_id": "vfs_tmp_only",
      "operation": "file-read*",
      "requested_path": "/private/tmp/foo",
      "expected_decision": "deny",
      "notes": "canonicalization makes /tmp literal ineffective"
    }
    // ...
  ]
  ```
  The generated matrix also includes `file-write*` entries.

- `out/runtime_results.json` – array of entries:

  ```jsonc
  [
    {
      "profile_id": "vfs_tmp_only",
      "operation": "file-read*",
      "requested_path": "/tmp/foo",
      "observed_path": "/private/tmp/foo", // from F_GETPATH if open succeeds
      "observed_path_source": "fd_path", // or "requested_path" fallback
      "observed_path_nofirmlink": "/System/Volumes/Data/private/tmp/foo", // when available
      "observed_path_nofirmlink_source": "fd_path", // or "unavailable"/"not_attempted"
      "decision": "allow",
      "errno": 0,
      "raw_log": {
        "exit_code": 0,
        "stdout": "...",
        "stderr": "..."
      }
    }
  ]
  ```

- `out/decode_tmp_profiles.json` – object keyed by `profile_id`:

  ```jsonc
  {
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
      ]
    }
  }
  ```

- `out/mismatch_summary.json` – coarse classification (base `/tmp` family only):

  ```jsonc
  {
    "world_id": "sonoma-14.4.1-23E224-arm64-dyld-2c0602c5",
    "profiles": {
      "vfs_tmp_only": {
        "kind": "canonicalization",
        "note": "Profile mentions only /tmp/foo; both /tmp/foo and /private/tmp/foo are denied; interpreted as canonicalization-before-enforcement, literal /tmp/foo ineffective."
      },
      "vfs_private_tmp_only": {
        "kind": "canonicalization",
        "note": "Profile mentions only /private/tmp/foo; both requests allowed; literal on canonical path effective."
      },
      "vfs_both_paths": {
        "kind": "control",
        "note": "Profile mentions both paths; both requests allowed; control confirming canonical behavior."
      }
    }
  }
  ```

Guardrails:

- A small structural test in `book/tests/` will assert:
  - `decode_tmp_profiles.json` exists and includes `vfs_tmp_only`, `vfs_private_tmp_only`, `vfs_both_paths`.
  - Each profile has anchor entries for both `/tmp/foo` and `/private/tmp/foo`.
- A shape test will assert:
  - `expected_matrix.json` and `runtime_results.json` exist.
  - Each entry carries the required fields (`profile_id`, `operation`, `requested_path`, `expected_decision` / `decision`, `observed_path`).
