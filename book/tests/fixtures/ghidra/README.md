# Ghidra fixtures

This guide covers Ghidra fixtures under:

- `book/tests/fixtures/ghidra_shapes/`
- `book/tests/fixtures/ghidra_canonical/`

All fixtures are scoped to `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.

## Shape snapshots (`ghidra_shapes/`)

- `manifest.json` defines the inventory of expected outputs.
  - Entries with `required: false` are best-effort; missing outputs are skipped.
- `manifest.strict.json` defines strict entries that must always exist.
  - Strict entries must appear in `manifest.json` and set `required: true`.
- `manifest.schema.json` documents the manifest schema.
- `families.json` groups entries for maintenance reporting.
- `*.shape.json` hold canonicalized shape signatures.

Test behavior:

- `book/tests/planes/ghidra/test_ghidra_output_shapes.py` validates available
  outputs in `manifest.json` and skips missing non-required entries.
- `book/tests/planes/ghidra/test_ghidra_output_shapes_strict_gate.py` enforces
  that strict entries are required and have outputs + snapshots present.
- `book/tests/planes/ghidra/test_ghidra_output_shapes_strict.py` validates every
  strict entry (always on).

Promotion ladder:

- **Inventory** → add to `manifest.json`.
- **Strict** → add to `manifest.strict.json` once it must never silently drift.
- **Sentinel** → add a canonical fixture only when it covers a new failure mode.

## Canonical sentinels (`ghidra_canonical/`)

- `*.json` holds the normalized output used by the sentinel test.
- `*.meta.json` records provenance (schema version, script path + hash, input
  path + hash, Ghidra version, analysis profile, world_id, output path).

Keep 1–3 canonical sentinels total and add new ones only for distinct failure
modes (new pipeline stage, normalization surface, or invariant class).

Dependency policy (current):

- Any `*.py` change under `book/api/ghidra/ghidra_lib/` (plus
  `book/api/ghidra/ghidra_bootstrap.py`) invalidates the sentinel and requires
  a refresh.

## Refresh workflow

- Run tests: `make -C book test`
- Refresh canonical sentinel:
  - `python -m book.api.ghidra.refresh_canonical --name offset_inst_scan_0xc0_write_classify`
  - `python -m book.api.ghidra.refresh_canonical --name kernel_collection_symbols_canary`
- Maintenance hygiene:
  - `python -m book.api.ghidra.shape_catalog_hygiene --report book/tests/fixtures/ghidra_shapes/catalog_report.json`
    - Add `--fail-on-issues` for a non-zero exit when issues are found.
- Optional prune/reseed:
  - `python -m book.api.ghidra.shape_manifest_prune --manifest book/tests/fixtures/ghidra_shapes/manifest.json \
      --report book/tests/fixtures/ghidra_shapes/prune_report.json --write --expand`

All paths must remain repo-relative in fixture metadata and manifests.
