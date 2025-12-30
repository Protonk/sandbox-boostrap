# CARTON (integration fixer bundle)

CARTON is the integration-time contract for SANDBOX_LORE: a small, reviewable bundle that freezes host-bound facts, their provenance, and the invariants we refuse to drift on. It is **not** a library API. The primary interface is **fix + verify + explain drift**.

## Layout

- `bundle/CARTON.json` — generated manifest (schema v2) with digest, role, size, and world binding.
- `bundle/relationships/` — canonical relationship outputs (operation coverage, profile-layer ops, anchor field2, etc.).
- `bundle/views/` — derived indices built from relationships (operation_index, profile_layer_index, filter_index, concept_index, anchor_index).
- `bundle/contracts/` — derived claim snapshots (review surface; not a query API).
- `spec/carton_spec.json` — declarative list of frozen artifacts and their hash policies.
- `spec/fixers.json` — fixer registry (ordering, module bindings, outputs).
- `spec/invariants.json` — status invariants we refuse to drift on.
- `fixers/` — relationship + view generators.
- `tools/` — CLI entrypoints (fix/update/check/diff).
- `schemas/` — JSON Schemas for contracts (validated by check).

## Workflow (update CARTON deliberately)

1. Refresh the bundle (front door):
   ```sh
   python -m book.integration.carton.tools.update
   ```
   or:
   ```sh
   make -C book carton-refresh
   ```
2. Review drift:
   ```sh
   python -m book.integration.carton.tools.diff
   ```
3. Optional: verify invariants explicitly:
   ```sh
   python -m book.integration.carton.tools.check
   ```
4. Run only fixers (no contracts/manifest):
   ```sh
   python -m book.integration.carton.tools.fix
   ```

Manual (advanced) steps:
- `python -m book.graph.mappings.run_promotion --generators runtime,system-profiles`
- `python -m book.integration.carton.tools.fix --ids relationships.operation_coverage`

## Notes

- All paths inside CARTON are repo-relative (use `book.api.path_utils`).
- Relationships are canonical; views are derived.
- Contract snapshots are *derived* from relationships; if they drift, regenerate them.
- `tools/check.py` fails on world mismatch or invariant regressions; update `spec/carton_spec.json` only when change is intentional.
