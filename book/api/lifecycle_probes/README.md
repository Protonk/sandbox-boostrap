# lifecycle_probes

Host-specific lifecycle probes for `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.

These probes exist to generate *validation IR* under:
- `book/graph/concepts/validation/out/lifecycle/`

and to feed the lifecycle mapping generator:
- `book/graph/mappings/runtime/generate_lifecycle.py`

## Probes

- `entitlements-evolution`
  - Builds and runs `c/entitlements_example.c`.
  - Writes a compact summary JSON (`entitlements_present`, signing identifier, executable path) to `entitlements.json`.

- `extensions-dynamic`
  - Builds and runs `c/extensions_demo.c`.
  - Writes a short notes log to `extensions_dynamic.md` (status is often `blocked` on this host without special entitlements).

## Run

Write both default lifecycle outputs:

```sh
python -m book.api.lifecycle_probes write-validation-out
```

Or write one output to an explicit path:

```sh
python -m book.api.lifecycle_probes entitlements --out book/graph/concepts/validation/out/lifecycle/entitlements.json
python -m book.api.lifecycle_probes extensions --out book/graph/concepts/validation/out/lifecycle/extensions_dynamic.md
```

Build products are written under `book/api/lifecycle_probes/build/` (not committed).

