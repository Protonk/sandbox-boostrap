# CARTON (integration fixer bundle)

CARTON is the integration-time contract for SANDBOX_LORE: a small, reviewable bundle that freezes host-bound facts, their provenance, and the invariants we refuse to drift on. The primary interface is **fix + verify + explain drift**.

## Layout

- `bundle/CARTON.json` — generated manifest (schema v2) with digest, role, size, and world binding.
- `bundle/relationships/` — canonical relationship outputs (operation coverage, profile-layer ops, anchor field2, etc.).
- `bundle/views/` — derived indices built from relationships (operation_index, profile_layer_index, filter_index, concept_index, anchor_index).
- `bundle/contracts/` — derived claim snapshots (review surface).
- `spec/carton_spec.json` — declarative list of frozen artifacts and their hash policies.
- `spec/fixers.json` — fixer registry (ordering, module bindings, outputs).
- `spec/invariants.json` — status invariants we refuse to drift on.
- `fixers/` — relationship + view generators.
- `tools/` — CLI entrypoints (fix/update/check/diff).
- `schemas/` — JSON Schemas for contracts (validated by check).

## Mental model

CARTON is a small, deterministic pipeline with a fixed flow. Mapping generators under `book/integration/carton/mappings/` publish host-scoped mapping JSON under `book/integration/carton/bundle/relationships/mappings/`. Fixers under `book/integration/carton/fixers/` then derive the canonical relationships and views under `book/integration/carton/bundle/relationships/` and `book/integration/carton/bundle/views/`. Finally, contracts and the manifest (`book/integration/carton/bundle/contracts/` and `book/integration/carton/bundle/CARTON.json`) snapshot those relationships so drift is reviewable.

Relationships are the canonical, reviewable layer. Views are derived indices. Contracts and the manifest are derived snapshots. If anything looks off, trace it backward along this chain: contracts/manifest -> relationships/views -> mappings -> upstream experiments and validation outputs.

Flow (overview):

```text
book/integration/carton/mappings/
  generators (runtime/system_profiles/vocab/...)
            |
            v
book/integration/carton/bundle/relationships/mappings/
  mapping JSON (host-scoped IR)
            |
            v
book/integration/carton/fixers/
  relationship + view builders
            |
            v
book/integration/carton/bundle/relationships/   book/integration/carton/bundle/views/
  canonical relationships                         derived indices
            |
            v
book/integration/carton/bundle/contracts/     book/integration/carton/bundle/CARTON.json
  contract snapshots                             manifest
```

## Mapping owners index

See `book/integration/carton/mappings/OWNERS.md` for a per-artifact map of generators, primary inputs, and guardrail tests for everything under `book/integration/carton/bundle/relationships/mappings/`.

## Workflow (update CARTON deliberately)

1. Refresh the bundle (front door):
   ```sh
   python -m book.integration.carton build
   ```
   or:
   ```sh
   make -C book carton-refresh
   ```
2. Review drift:
   ```sh
   python -m book.integration.carton diff
   ```
3. Optional: verify invariants explicitly:
   ```sh
   python -m book.integration.carton check
   ```
4. Run only fixers (no contracts/manifest):
   ```sh
   python -m book.integration.carton fix
   ```

Manual (advanced) steps:
- `python -m book.integration.carton promote`
- `python -m book.integration.carton fix --jobs relationships.operation_coverage`

## Tooling guide (what to run when)

- `python -m book.integration.carton build`: full refresh (optional promotion, fixers, contracts, manifest, check). Use this after mapping inputs change or when you want a clean, end-to-end rebuild.
- `python -m book.integration.carton fix`: rebuild relationships and views only. Use this when mapping JSON is already up to date but derived indices are stale.
- `python -m book.integration.carton check`: validate world bindings, schema shapes, and contract drift. Use this to confirm a clean state without rewriting outputs.
- `python -m book.integration.carton diff`: review drift between expected and current bundle outputs.
- `make -C book test`: CI front door that runs the Swift graph build and CARTON refresh/check.

## Troubleshooting

- Contract drift in `book/integration/carton/bundle/contracts/*.json`: regenerate via `python -m book.integration.carton build`; if drift persists, inspect `book/integration/carton/bundle.py` and the corresponding relationship JSON.
- View drift in `book/integration/carton/bundle/views/*.json`: inspect `book/integration/carton/fixers/build_views.py` and the input relationships it consumes.
- Missing or stale manifest entries in `book/integration/carton/bundle/CARTON.json`: update `book/integration/carton/spec/carton_spec.json` when adding/removing artifacts, then rerun `python -m book.integration.carton build`.
- World mismatch failures: confirm the baseline in `book/world/sonoma-14.4.1-23E224-arm64/world.json` and rerun the generator that owns the affected mapping.

## Notes

- All paths inside CARTON are repo-relative (use `book.api.path_utils`).
- Relationships are canonical; views are derived.
- Contract snapshots are *derived* from relationships; if they drift, regenerate them.
- `python -m book.integration.carton check` fails on world mismatch or invariant regressions; update `spec/carton_spec.json` only when change is intentional.
- Specs (`spec/carton_spec.json`, `spec/fixers.json`, `spec/invariants.json`) are generated from the registry; update `book/integration/carton/core/registry.py` instead of hand-editing the JSON.
