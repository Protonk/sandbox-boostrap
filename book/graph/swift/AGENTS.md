# Agents in `book/graph/swift/`

Purpose: Swift generator/validator for graph-level artifacts. It parses `book/substrate/Concepts.md` + inventory markdown, emits JSON used by the textbook and CARTON, and hosts static enforcement for stable mappings encoded as Swift data structures.

Run: `make -C book test` (preferred) or `swift run` from `book/graph/` after sourcing the repo venv. The CI driver (`book/ci.py`) invokes this target automatically.

Modify:
- Add Swift types/validators for new schema slices (e.g., vocab attestations, coverage summaries, tag layouts) under this directory, not elsewhere.
- Keep validation non-fatal: emit reports to `book/graph/concepts/validation/validation_report.json` rather than crashing. Encode “always-enforced” mapping invariants as typed Swift structures so drift is caught at build time.
- Keep paths relative to `book/graph/` and document any new inputs/outputs in `book/graph/swift/README.md`.

Do not:
- Move ingestion/decoder logic here; it stays in `book/graph/concepts/validation/` (Python).
- Hand-wire paths outside `book/graph/` or depend on experiment scratch outputs.
- Bypass `make -C book test`; that target is the single entrypoint the root `AGENTS.md` documents.***
