# Ghidra shape fixtures

These fixtures pin the JSON output shapes for a small set of Ghidra scripts on
`world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.

- `manifest.json` defines the output files and snapshot locations.
- `manifest.strict.json` defines the strict set (host-bound) for always-on gating.
- `manifest.schema.json` documents the schema used by the manifest.
- `*.shape.json` files hold the canonicalized shape signatures.

The shape tests are best-effort: if the referenced output files are missing
(e.g., no local `dumps/` artifacts), the tests skip unless the entry is marked
`"required": true`.

Strict shapes are enforced by `book/tests/test_ghidra_output_shapes_strict_gate.py`.
Setting `GHIDRA_STRICT_SHAPES=1` additionally runs the optional strict test.
