# Ghidra shape fixtures

These fixtures pin the JSON output shapes for a small set of Ghidra scripts on
`world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.

## Promotion ladder (social contract)

- **Tier 0 (inventory):** `manifest.json` + shape snapshot. Usually `"required": false`.
- **Tier 1 (canary):** `manifest.strict.json` entries. Always `"required": true` and always-on gating.
- **Tier 2 (sentinel):** canonical fixtures in `book/tests/fixtures/ghidra_canonical/` with
  schema-versioned provenance and value invariants.

Promotion criteria:
- Promote to **strict** when you’d rather fail fast than silently lose or reshape that output.
- Promote to **sentinel** only when it covers a new failure mode (new pipeline stage, new
  normalization surface, or new class of invariants), not just “another output you like.”

- `manifest.json` defines the output files and snapshot locations.
- `manifest.strict.json` defines the strict set (host-bound) for always-on gating.
- `manifest.schema.json` documents the schema used by the manifest.
- `families.json` groups entries for maintenance-only reporting/pruning.
- `*.shape.json` files hold the canonicalized shape signatures.

The shape tests are best-effort: if the referenced output files are missing
(e.g., no local `dumps/` artifacts), the tests skip unless the entry is marked
`"required": true`.

Strict shapes are enforced by `book/tests/planes/ghidra/test_ghidra_output_shapes_strict_gate.py`.
Setting `GHIDRA_STRICT_SHAPES=1` additionally runs the optional strict test.

## Workflow (single-path commands)

- Run tests: `make -C book test`
- Refresh canonical sentinel: `python -m book.api.ghidra.refresh_canonical --name offset_inst_scan_0xc0_write_classify`
- Maintenance hygiene: `python -m book.api.ghidra.shape_catalog_hygiene --report book/tests/fixtures/ghidra_shapes/catalog_report.json`
  - Add `--fail-on-issues` for a non-zero exit when issues are found.
