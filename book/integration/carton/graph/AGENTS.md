# Agents in `book/integration/carton/graph/`

Purpose: Swift graph tool for concept inventory and routing metadata. It generates the concept JSONs and enforces stable mapping invariants at build time.

Run:
- `make -C book test` (preferred)
- `python -m book.integration.carton swift --run`

Do:
- Keep graph-related Swift code under `book/integration/carton/graph/swift/`.
- Document new inputs/outputs in `book/integration/carton/graph/README.md` and `book/integration/carton/graph/swift/README.md`.

Do not:
- Put ingestion/decoder logic here; that lives under `book/integration/carton/validation/`.
