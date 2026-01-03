# CARTON Graph Tool

This target keeps the concept inventory and routing metadata in sync with the rest of the repo. It is intentionally small and typed so changes stay visible and reproducible.

What it does (current):
- Parses `book/substrate/Concepts.md` + `book/evidence/graph/concepts/CONCEPT_INVENTORY.md` + `book/integration/carton/Concept_map.md`.
- Emits JSON: `book/evidence/graph/concepts/{concepts.json,concept_map.json,concept_text_map.json}`, `book/evidence/graph/concepts/validation/{strategies.json,validation_report.json}`.
- Runs light validation (concept IDs referenced by strategies and runtime expectations exist) and writes `book/evidence/graph/concepts/validation/validation_report.json`.
- Reads the CARTON inventory graph (`book/integration/carton/bundle/relationships/inventory/inventory_graph.json`) for typed validation hints, including experiment enrollments.
- Feeds stable mappings into CARTON fixers (see `book/integration/carton/bundle/CARTON.json`), the frozen CARTON bundle (relationships/views/contracts + manifest) used by the textbook and CI guardrails.
- Encodes “always enforced” mapping invariants as Swift data structures; the Swift build fails if the host mappings drift (see `swift/`).

How to run:
```
python -m book.integration.carton swift --run
```
Outputs are written in place. Existing `concept_text_map.json` is respected and reused.

Extending it:
- Add new Swift types for one JSON slice at a time (e.g., attestations, runtime manifests).
- Parse and validate against the generated `concepts.json` and host manifests.
- Emit a small report under `book/evidence/graph/concepts/validation/` (prefer `out/` or `validation_report.json`) rather than failing silently.
- Document new coverage in `book/integration/carton/graph/README.md` and `book/integration/carton/graph/swift/README.md`.
- Keep static mapping invariants (vocab/coverage/digests/tag layouts/manifest/literal expectations) in Swift so drift is caught by `make -C book test`.

Directory map (agent quick reference):
- `swift/` – Swift generator/validator, split by concern (types/utils, concept parsing, strategies, bindings, entrypoint).
- `book/evidence/graph/concepts/` – Concept inventory sources and generated JSON (plus Swift validation reports under `book/evidence/graph/concepts/validation/`).
- `book/integration/carton/mappings/` – Generators for stable host-specific IR (vocab, op_table, anchors, tag_layouts, system_profiles, runtime) that live under `book/integration/carton/bundle/relationships/mappings/` and feed into CARTON fixers.
- CARTON bundle lives under `book/integration/carton/` (relationships, views, contracts, manifest, and tools).
