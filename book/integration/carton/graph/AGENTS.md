# Agents in `book/integration/carton/graph/`

Purpose: Swift graph tool that parses `book/integration/carton/Concept_map.md` and emits `concepts.json` + `concept_map.json`.

Run:
- `make -C book test` (preferred)
- `python -m book.integration.carton swift --run`

Do:
- Keep Swift parsing under `book/integration/carton/graph/swift/`.
- Document inputs/outputs in `book/integration/carton/graph/README.md` and `book/integration/carton/graph/swift/README.md`.

Do not:
- Add validation/decoder logic here; that lives under `book/integration/carton/validation/`.
