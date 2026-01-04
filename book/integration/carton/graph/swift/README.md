# Swift checks (`book/integration/carton/graph/swift/`)

This directory holds the Swift executable target that maps the curated concept map markdown into JSON used elsewhere in the repo.

- **Entry point:** `python -m book.integration.carton swift --run` (normally invoked via `make -C book test`, which calls `book/integration/ci.py` → Swift build).
- **Input:** `book/integration/carton/Concept_map.md`.
- **Outputs:** regenerated `concepts.json` and `concept_map.json` under `book/evidence/syncretic/concepts/`.
- **Make targets:** `make -C book build` runs Python + Swift with module caches pinned to `book/integration/carton/graph/.module-cache`; `make -C book clean` resets SwiftPM/.build/module caches.

Files are split by concern (types/utils, concept parsing, main). Keep the generator tight and deterministic.
