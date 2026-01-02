# Book Graph Generator

This target keeps the concept inventory and routing metadata in sync with the rest of the repo. It is intentionally small and typed so changes stay visible and reproducible.

What it does (current):
- Parses `book/substrate/Concepts.md` + `book/evidence/graph/concepts/CONCEPT_INVENTORY.md` + `book/graph/concepts/validation/Concept_map.md`.
- Emits JSON: `book/graph/concepts/{concepts.json,concept_map.json,concept_text_map.json}`, `book/graph/concepts/validation/{strategies.json,validation_report.json}`, `book/examples/examples.json`.
- Runs light validation (concept IDs referenced by strategies and runtime expectations exist) and writes `book/evidence/graph/concepts/validation/validation_report.json`.
- Feeds stable mappings into CARTON fixers (see `book/integration/carton/bundle/CARTON.json`), the frozen CARTON bundle (relationships/views/contracts + manifest) used by the textbook and CI guardrails.
- Encodes “always enforced” mapping invariants as Swift data structures; the Swift build fails if the host mappings drift (see `swift/`).

How to run:
```
cd book/graph
swift run
```
Outputs are written in place. Existing `concept_text_map.json` is respected and reused.

Extending it:
- Add new Swift types for the JSON slice you want to validate (e.g., attestations, runtime manifests).
- Parse and validate against the generated `concepts.json` and host manifests.
- Emit a small report under `book/graph/concepts/validation/` rather than failing silently.
 - Keep static mapping invariants (vocab/coverage/digests/tag layouts/manifest/literal expectations) in Swift so drift is caught by `make -C book test`.

Directory map (agent quick reference):
- `swift/` – Swift generator/validator, split by concern (types/utils, concept parsing, strategies, examples, bindings, entrypoint).
- `concepts/` – Concept inventory source (markdown), generated JSON, validation metadata, and Swift validation reports.
- `mappings/` – Stable host-specific IR (vocab, op_table, anchors, tag_layouts, system_profiles, runtime) that mapping generators feed into CARTON fixers.
- CARTON bundle lives under `book/integration/carton/` (relationships, views, contracts, manifest, and tools).
- `regions/` – Generated chapter/section map for the textbook.
