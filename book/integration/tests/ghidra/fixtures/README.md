# Ghidra test fixtures

This repo’s only committed pytest fixtures are for the Ghidra plane, so they
live next to the Ghidra tests.

All fixtures here are host-bound and scoped to the Sonoma baseline
(`world_id sonoma-14.4.1-23E224-arm64-dyld-a3a840f9`).

## Layout

### Shape catalog (`shape_catalog/`)

The shape catalog pins the **JSON structure** of selected Ghidra task outputs
under `book/evidence/dumps/ghidra/out/<build>/...` without re-running Ghidra in tests.

- `shape_catalog/manifest.json` — inventory of outputs and their snapshot paths.
- `shape_catalog/manifest.strict.json` — strict subset that must always exist and validate.
- `shape_catalog/manifest.schema.json` — schema for the manifests.
- `shape_catalog/families.json` — grouping/overrides for maintenance reporting.
- `shape_catalog/snapshots/*.shape.json` — canonicalized shape snapshots.
- `shape_catalog/reports/` — maintenance outputs (not used by pytest; safe to regenerate).

Tests:
- `book/integration/tests/ghidra/test_ghidra_output_shapes.py` validates available
  outputs listed in `manifest.json` (missing non-required outputs are skipped).
- `book/integration/tests/ghidra/test_ghidra_output_shapes_strict_gate.py` enforces that
  strict entries are required and have outputs + snapshots present.
- `book/integration/tests/ghidra/test_ghidra_output_shapes_strict.py` validates every
  strict entry.

Promotion ladder:
- Add a new entry to `manifest.json` first.
- Promote to `manifest.strict.json` only when you want always-on gating (missing
  output should fail fast, not silently skip).

### Canonical sentinels (`canonical/`)

Canonical sentinels lock **high-signal normalized outputs** (not just shapes)
to catch semantic drift in normalization/wiring.

- `canonical/*.json` — normalized output fixture.
- `canonical/*.meta.json` — provenance sidecar (script path+hash, input+hash,
  depset, world_id, normalizer id).

Keep canonical sentinels few (1–3) and only add one when it protects a new
failure mode (new pipeline stage, normalization surface, or invariant class).

## Workflows

- Run tests: `make -C book test`

- Prune/reseed shape coverage from existing outputs:

  `python -m book.api.ghidra.shape_manifest_prune --manifest book/integration/tests/ghidra/fixtures/shape_catalog/manifest.json --report book/integration/tests/ghidra/fixtures/shape_catalog/reports/prune_report.json --write --expand`

- Shape catalog hygiene report:

  `python -m book.api.ghidra.shape_catalog_hygiene --report book/integration/tests/ghidra/fixtures/shape_catalog/reports/catalog_report.json`

  Add `--fail-on-issues` for a non-zero exit when issues are found.

- Refresh canonical sentinel fixtures from already-generated outputs:
  - `python -m book.api.ghidra.refresh_canonical --name offset_inst_scan_0xc0_write_classify`
  - `python -m book.api.ghidra.refresh_canonical --name kernel_collection_symbols_canary`

## Path hygiene

All fixture metadata and manifests must remain repo-relative. Do not embed
absolute host paths in committed JSON.
