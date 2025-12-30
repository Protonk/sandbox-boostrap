# CARTON (integration contract bundle)

CARTON is the integration-time contract for SANDBOX_LORE: a small, reviewable bundle that freezes host-bound facts, their provenance, and the invariants we refuse to drift on. It is **not** a library API. The primary interface is **freeze + verify + explain drift**.

## Layout

- `carton_spec.json` — declarative list of frozen artifacts and their hash policies.
- `CARTON.json` — generated manifest (schema v2) with digest, role, size, and world binding.
- `build_manifest.py` — spec-driven manifest builder (optionally regenerates contracts).
- `check.py` — CI entrypoint: verify hashes, world binding, schemas, and invariants.
- `diff.py` — human-focused drift report (manifest vs live artifacts).
- `contracts/` — derived claim snapshots (review surface; not a query API).
- `schemas/` — optional JSON Schemas for contracts (validated by `check.py`).

## Workflow (update CARTON deliberately)

1. Refresh upstream mappings/IR:
   ```sh
   python -m book.graph.mappings.run_promotion --generators runtime,system-profiles,carton-coverage,carton-indices
   ```
2. Regenerate contract snapshots:
   ```sh
   python -m book.integration.carton.build_manifest --refresh-contracts --skip-manifest
   ```
3. Refresh the manifest:
   ```sh
   python -m book.integration.carton.build_manifest
   ```
4. Review drift:
   ```sh
   python -m book.integration.carton.diff
   ```
5. Verify invariants:
   ```sh
   python -m book.integration.carton.check
   ```

## Notes

- All paths inside CARTON are repo-relative (use `book.api.path_utils`).
- Contract snapshots are *derived* from mappings; if they drift, regenerate them.
- `check.py` fails on world mismatch or invariant regressions; update `carton_spec.json` only when change is intentional.
