# Test fixtures

Fixtures under `book/tests/fixtures/` are stable inputs/outputs consumed by the
pytest suite. They are not generated during test runs.

## Rules

- Keep paths repo-relative; do not embed absolute host paths.
- Treat fixtures as host-bound; preserve `world_id` metadata where present.
- Regenerate fixtures via their owning tool; avoid hand-editing.

## Updates

- If fixture content changes, update any related hashes/indices
  (for example `book/graph/concepts/validation/fixtures/fixtures.json`).
- Ghidra-specific fixtures are documented in `book/tests/fixtures/ghidra/README.md`.
