# VFS Canonicalization – Plan (Sonoma baseline)

## Purpose and question

This experiment focuses on **VFS canonicalization between `/tmp` and `/private/tmp`** on the fixed Sonoma world (`world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`).

Core questions:

- For simple, controlled SBPL profiles, how does PolicyGraph structure and runtime behavior differ when rules mention only `/tmp/foo` vs only `/private/tmp/foo` vs both?
- Where do we see differences between what the SBPL “says” and what the runtime does that can be fairly attributed to VFS canonicalization (e.g., `/tmp` → `/private/tmp`), rather than to decoder bugs or policy differences?

Scope: file-read semantics only, for the path pairs `/tmp/foo` ↔ `/private/tmp/foo`, `/tmp/bar` ↔ `/private/tmp/bar`, `/tmp/nested/child` ↔ `/private/tmp/nested/child`, and a control `/var/tmp/canon` ↔ `/private/var/tmp/canon` on this host.

## Relationship to existing work

Upstream inputs:

- **Tag and layout bedrock:** `book/graph/mappings/tag_layouts/tag_layouts.json` (status: ok, from `tag-layout-decode`).
- **Anchor/field2 structure:** `book/experiments/probe-op-structure/Report.md` + `out/anchor_hits.json`, plus curated anchors in `book/graph/mappings/anchors/anchor_filter_map.json` (guarded by `book/tests/test_anchor_filter_alignment.py`). In particular, `/tmp/foo` anchor placement and tag/field2 usage.
- **Field2 inventories:** `book/experiments/field2-filters/Report.md` with `out/field2_inventory.json` and `out/unknown_nodes.json` for high/unknown field2 values.
- **Runtime harness:** `book/api/runtime_harness.runner.run_expected_matrix` (same harness used by `runtime-checks` / `runtime-adversarial`).

Downstream use:

- Provide a small, well-documented set of structural and runtime examples for `/tmp` ↔ `/private/tmp` behavior that chapters, runtime experiments, and mappings can cite when they talk about path normalization and canonicalization on this world.

## Design and probes

Profiles live under `book/experiments/vfs-canonicalization/sb/`:

- `vfs_tmp_only.sb`:
  - `(deny default)` plus `(allow file-read* (literal "/tmp/foo"))`.
- `vfs_private_tmp_only.sb`:
  - `(deny default)` plus `(allow file-read* (literal "/private/tmp/foo"))`.
- `vfs_both_paths.sb`:
  - `(deny default)` plus both allow rules:
    - `(allow file-read* (literal "/tmp/foo"))`
    - `(allow file-read* (literal "/private/tmp/foo"))`.

Compiled blobs will be written to `sb/build/<stem>.sb.bin` using `book.api.profile_tools.compile_sbpl_string`.

Scenarios:

- For each profile, attempt `file-read*` on all alias/canonical pairs listed above.
- Observe:
  - Structural placement of the anchors and field2 values in the compiled graphs.
  - Runtime allow/deny behavior under an SBPL/ blob harness.

## Evidence pathway (Claim → Signals → IR)

Claims we are probing:

1. **Canonicalization claim:** For this world, `/tmp/foo` and `/private/tmp/foo` refer to the same effective path in the VFS layer; if they differ structurally or at runtime, we should be able to classify that difference as either canonicalization-only or as a true policy divergence.
2. **Structural/runtime alignment claim:** For the simple VFS profiles above, structural expectations (anchors, tags, field2) match the runtime allow/deny behavior once canonicalization is taken into account.

Signals:

- **Structural (static) signals:**
  - Decoded nodes and literal/anchor placement for `/tmp/foo` and `/private/tmp/foo` in each profile:
    - tags,
    - `field2` values,
    - whether the two paths share the same structural placement or not.
  - Stored in `out/decode_tmp_profiles.json`.
- **Runtime signals:**
  - For each `(profile_id, requested_path)` pair:
    - decision (`allow` / `deny` / `error`),
    - errno (if any),
    - command output (stdout/stderr).
  - Stored in `out/runtime_results.json` (simple array form) with `profile_id`, `operation`, `requested_path`, `observed_path`, `decision`, `errno`, `raw_log`.
- **Logical expectations:**
  - For each `(profile_id, requested_path)` we record our **initial expectation** (e.g., “allow only for the literal path mentioned in SBPL, deny the other”) in `out/expected_matrix.json`. Mismatches between `expected_decision` and `decision` in runtime are where canonicalization or divergences show up.

IR path:

- `Plan.md` (this file) encodes the question, design, and JSON shapes.
- `run_vfs.py` (harness script) will:
  - compile profiles,
  - emit `out/expected_matrix.json` (simple, pre-run expectations scoped to this experiment),
  - build a harness-specific matrix and call `book.api.runtime_harness.runner.run_expected_matrix`,
  - down-convert the harness runtime results into `out/runtime_results.json` (authoritative runtime behavior for this suite on this world),
  - emit `out/decode_tmp_profiles.json` via `book/api/decoder` (structural view),
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

- `out/runtime_results.json` – array of entries:

  ```jsonc
  [
    {
      "profile_id": "vfs_tmp_only",
      "operation": "file-read*",
      "requested_path": "/tmp/foo",
      "observed_path": "/tmp/foo", // or canonicalized form if available
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

- `out/mismatch_summary.json` – coarse classification:

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
