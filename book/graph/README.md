# Book Graph Generator

This target keeps the concept inventory and routing metadata in sync with the rest of the repo. It is intentionally small and typed so changes stay visible and reproducible.

What it does (current):
- Parses `substrate/Concepts.md` + `book/graph/concepts/CONCEPT_INVENTORY.md` + `book/graph/concepts/validation/Concept_map.md`.
- Emits JSON: `book/graph/concepts/{concepts.json,concept_map.json,concept_text_map.json}`, `book/graph/concepts/validation/strategies.json`, `book/examples/examples.json`.
- Runs light validation (concept IDs referenced by strategies and runtime expectations exist) and writes `book/graph/validation/validation_report.json`.

How to run:
```
cd book/graph
swift run
```
Outputs are written in place. Existing `concept_text_map.json` is respected and reused.

Extending it:
- Add new Swift types for the JSON slice you want to validate (e.g., attestations, runtime manifests).
- Parse and validate against the generated `concepts.json` and host manifests.
- Emit a small report under `book/graph/validation/` rather than failing silently.

Directory map (agent quick reference):
- `Sources/` – Swift generator/validator (see `main.swift`).
- `concepts/` – Concept inventory source (markdown), generated JSON, and validation metadata.
- `mappings/` – Stable host-specific IR (vocab, op_table, anchors, tag_layouts, system_profiles, runtime).
- `regions/` – Generated chapter/section map for the textbook.
- `validation/` – Validation reports from the Swift pass and any future schema checks.
