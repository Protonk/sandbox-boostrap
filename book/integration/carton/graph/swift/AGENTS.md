# Agents in `book/integration/carton/graph/swift/`

Purpose: Swift generator/validator for graph-level artifacts. It parses `book/substrate/Concepts.md` + inventory markdown, emits JSON used by the textbook and CARTON, and hosts static enforcement for stable mappings encoded as Swift data structures.

Run: `make -C book test` (preferred) or `python -m book.integration.carton swift --run` after sourcing the repo venv. The CI driver (`book/integration/ci.py`) invokes the Swift build automatically.

Modify:
- Add Swift types/validators for new schema slices (e.g., vocab attestations, coverage summaries, tag layouts) under this directory, not elsewhere.
- Reuse generated `concepts.json` for ID checks and emit reports under `book/evidence/graph/concepts/validation/` (prefer `out/` or `validation_report.json`) rather than crashing.
- Encode “always-enforced” mapping invariants as typed Swift structures so drift is caught at build time.
- Keep paths relative to repo root and document any new inputs/outputs in `book/integration/carton/graph/README.md` and `book/integration/carton/graph/swift/README.md`.

Do not:
- Move ingestion/decoder logic here; it stays in `book/integration/carton/validation/` (Python).
- Hand-wire paths outside the repo root or depend on experiment scratch outputs.
- Bypass `make -C book test`; that target is the single entrypoint the root `AGENTS.md` documents.***
