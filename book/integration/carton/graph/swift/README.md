# Swift checks (`book/integration/carton/graph/swift/`)

This directory holds the Swift executable target that enforces static contracts over stable graph artifacts (concept inventory JSON, strategy routing, and any mapping invariants promoted to “always enforced” status).

- **Entry point:** `python -m book.integration.carton swift --run` (normally invoked via `make -C book test`, which calls `book/integration/ci.py` → Swift build).
- **Inputs:** `book/substrate/Concepts.md`, `book/evidence/graph/concepts/CONCEPT_INVENTORY.md`, `book/integration/carton/Concept_map.md`, `book/integration/carton/bundle/relationships/mappings/runtime/expectations.json`, `book/integration/carton/bundle/relationships/inventory/inventory_graph.json` (including experiment enrollments), and any mapping JSONs you load here explicitly.
- **Outputs:** regenerated `concepts.json`, `concept_map.json`, `concept_text_map.json`, `strategies.json`, and `validation_report.json` under `book/evidence/graph/concepts/` + `book/evidence/graph/concepts/validation/`.
- **Static enforcement:** encode stable mappings (vocab/coverage/digests/tag layouts/manifest/literals) as Swift data structures and validate them here so drift is caught during the Swift build.
- **Make targets:** `make -C book build` runs Python + Swift with module caches pinned to `book/integration/carton/graph/.module-cache`; `make -C book clean` resets SwiftPM/.build/module caches.

Files are split by concern (types/utils, concept parsing, strategies, bindings, main). Keep new checks small and typed, with clear provenance comments pointing back to mapping paths and validation outputs.
