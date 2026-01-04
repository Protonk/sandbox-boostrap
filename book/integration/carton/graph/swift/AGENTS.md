# Agents in `book/integration/carton/graph/swift/`

Purpose: Swift generator for the concept inventory JSONs derived from `book/integration/carton/Concept_map.md`.

Run: `make -C book test` (preferred) or `python -m book.integration.carton swift --run` after sourcing the repo venv. The CI driver (`book/integration/ci.py`) invokes the Swift build automatically.

Modify:
- Keep paths relative to repo root and document new inputs/outputs in `book/integration/carton/graph/README.md` and `book/integration/carton/graph/swift/README.md`.

Do not:
- Move ingestion/decoder logic here; it stays in `book/integration/carton/validation/` (Python).
- Hand-wire paths outside the repo root or depend on experiment scratch outputs.
- Bypass `make -C book test`; that target is the single entrypoint the root `AGENTS.md` documents.***
