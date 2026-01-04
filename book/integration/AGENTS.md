# Agents in `book/integration/`

This directory holds the pytest guardrail suite for SANDBOX_LORE. The goal is
to make drift obvious (mappings, contracts, fixtures, and tool wiring) without
turning tests into a second copy of the book.

## Run

- Only supported runner: `make -C book test` (pytest + Swift graph build via `book/integration/ci.py`).

## Router (where things live)

Pick the smallest plane that “owns” the invariant:

- `book/integration/tests/smoke` — import/wiring sanity (fast failures).
- `book/integration/tests/contracts` — decoder/profile/SBPL API & CLI contracts.
- `book/integration/tests/graph` — concepts, vocab, mappings, anchors, validation IR alignment.
- `book/integration/tests/carton` — CARTON relationships/views/contracts/manifest invariants.
- `book/integration/tests/runtime` — normalized runtime artifacts, promotion packet shapes, lifecycle cross-checks.
- `book/integration/tests/ghidra` — Ghidra scan outputs and fixture guardrails.
- `book/integration/tests/tools` — preflight/gate minimizer/trace shrink/frida/entitlement tooling.
- `book/integration/tests/examples` — example directories and experiment output shape checks.

Fixtures and fixture policy:

- `book/integration/tests/ghidra/fixtures/README.md`

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
  line are captured under `book/integration/out/` for debugging.
- Don’t hand-edit generated/shared artifacts (mappings, CARTON bundle files listed in `book/integration/carton/bundle/CARTON.json`,
  generated concept JSON). Update sources and rerun the generator.

## Fixtures (how changes should land)

- Treat fixtures as inputs to tests, not outputs of test runs.
- Regenerate fixtures via the owning tool; avoid hand-editing.
- If a fixture change affects hashes/indices, update
  `book/evidence/syncretic/validation/fixtures/fixtures.json` (and any other
  contract that pins that fixture) in the same change.
