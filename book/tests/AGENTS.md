# Agents in `book/tests/`

This directory holds the pytest guardrail suite for SANDBOX_LORE. The goal is
to make drift obvious (mappings, contracts, fixtures, and tool wiring) without
turning tests into a second copy of the book.

## Run

- Only supported runner: `make -C book test` (pytest + Swift graph build via `book/ci.py`).

## Router (where things live)

Pick the smallest plane that “owns” the invariant:

- `book/tests/planes/smoke` — import/wiring sanity (fast failures).
- `book/tests/planes/contracts` — decoder/profile/SBPL API & CLI contracts.
- `book/tests/planes/graph` — concepts, vocab, mappings, anchors, validation IR alignment.
- `book/tests/planes/carton` — CARTON manifest/indices/query facade invariants.
- `book/tests/planes/runtime` — normalized runtime artifacts, promotion packet shapes, lifecycle cross-checks.
- `book/tests/planes/ghidra` — Ghidra scan outputs and fixture guardrails.
- `book/tests/planes/tools` — preflight/gate minimizer/trace shrink/frida/entitlement tooling.
- `book/tests/planes/examples` — example directories and experiment output shape checks.

Fixtures and fixture policy:

- `book/tests/fixtures/README.md`
- `book/tests/fixtures/ghidra/README.md`

## Marks (keep the suite honest)

- Use `@pytest.mark.system` for anything that shells out, touches macOS system
  surfaces, or depends on Apple tooling.
- Use `@pytest.mark.smoke` only for tests we expect to stay extremely cheap and
  high-signal.

## Test invariants (non-negotiable style)

- Treat these as sanity checks, not semantic proofs. Don’t “test macOS”, test
  our wiring and our pinned artifacts.
- Keep tests deterministic and quick. Prefer structural assertions over long
  probes.
- Use repo-relative paths in assertions and emitted artifacts; normalize via
  `book.api.path_utils` helpers instead of embedding `/Users/...`.
- Use the `run_cmd` fixture for subprocesses so stdout/stderr and the command
  line are captured under `book/tests/out/` for debugging.
- Don’t hand-edit generated/shared artifacts (mappings, CARTON-listed files,
  generated concept JSON). Update sources and rerun the generator.

## Fixtures (how changes should land)

- Treat fixtures as inputs to tests, not outputs of test runs.
- Regenerate fixtures via the owning tool; avoid hand-editing.
- If a fixture change affects hashes/indices, update
  `book/graph/concepts/validation/fixtures/fixtures.json` (and any other
  contract that pins that fixture) in the same change.
