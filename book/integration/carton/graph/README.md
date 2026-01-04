# CARTON Graph Tool

This target keeps the concept inventory JSONs in sync with the curated concept map. It is intentionally small and typed so changes stay visible and reproducible.

What it does (current):
- Parses `book/integration/carton/Concept_map.md`.
- Emits JSON: `book/evidence/carton/concepts/{concepts.json,concept_map.json}`.

How to run:
```
python -m book.integration.carton swift --run
```
Outputs are written in place.

Extending it:
- Keep new checks or validation logic out of this tool; it should only map markdown → JSON.
- Document any input/output changes in `book/integration/carton/graph/README.md` and `book/integration/carton/graph/swift/README.md`.

Directory map (agent quick reference):
- `swift/` – Swift generator (types/utils, concept parsing, entrypoint).
- `book/evidence/carton/concepts/` – Generated concept JSON outputs.
- `book/integration/carton/mappings/` – Generators for stable host-specific IR (vocab, op_table, anchors, tag_layouts, system_profiles, runtime) that live under `book/integration/carton/bundle/relationships/mappings/` and feed into CARTON fixers.
- CARTON bundle lives under `book/integration/carton/` (relationships, views, contracts, manifest, and tools).
