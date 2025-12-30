# Testing in `book/`

The test suite is a host-bound guardrail for the active Sonoma baseline. It is
intentionally conservative: it prefers catching drift in **our artifacts and
tooling** (mappings, contracts, fixtures, and plumbing) over trying to prove
sandbox semantics in the abstract.

If you want semantic claims, the repo’s contract is: collect evidence into
experiments → normalize into validation IR → promote into mappings/CARTON. The
tests then pin those promoted surfaces so they don’t silently change.

## Running tests

- Single supported entrypoint: `make -C book test`.
- Direct pytest (local/dev): `PYTHONPATH=$(pwd) python -m pytest` from repo root.
- Use markers to scope work:
  - `-m system` runs only system-dependent tests.
  - `-m "not system"` skips system-dependent tests.

## Artifacts and debugging

Every run clears `book/integration/out/` and then writes a single set of artifacts for
that run (no timestamps/UUIDs).

- `book/integration/out/run.json` — run metadata (python, platform, resolved world_id when available).
- `book/integration/out/summary.json` — totals + exit status.
- `book/integration/out/<nodeid>/...` — per-test directory:
  - `report.json` always
  - `failure.txt` on failures
  - `stdout.txt` / `stderr.txt` / `command.json` when the test uses `run_cmd`

When debugging a failing subprocess test, start at that test’s `command.json`
and read `stderr.txt` alongside it.

## Writing tests (what “good” looks like here)

### 1) Put the test in the right plane

Choose the smallest plane that owns the invariant:

- `book/integration/tests/smoke` — import/wiring sanity (fast failures).
- `book/integration/tests/contracts` — decoder/profile/SBPL API & CLI contracts.
- `book/integration/tests/graph` — concepts, vocab, mappings, anchors, validation IR alignment.
- `book/integration/tests/carton` — CARTON manifest/indices/query facade invariants.
- `book/integration/tests/runtime` — normalized runtime artifacts and promotion packet shapes.
- `book/integration/tests/ghidra` — Ghidra scan outputs + fixture guardrails.
- `book/integration/tests/tools` — preflight/gate minimizer/trace shrink/frida/entitlement tooling.
- `book/integration/tests/examples` — example dirs and experiment output shape checks.

If you’re unsure, prefer `contracts` (API surfaces) or `graph` (host-pinned IR).

### 2) Keep tests discriminating

A useful guardrail answers “what broke?” without a second debugging session:

- Assert a small number of high-signal facts (shape, metadata, pinned IDs, cross-file alignment).
- Prefer one clear failure message over many cascading asserts.
- Avoid re-deriving expensive artifacts inside tests; consume the promoted JSON/fixtures instead.

### 3) Be explicit about system dependence

Mark anything that shells out, touches macOS system surfaces, or depends on
Apple tooling with `@pytest.mark.system`.

### 4) Use the standard helpers

- Use `run_cmd` for subprocess calls so stdout/stderr and the argv/cwd are captured.
- Normalize paths using `book.api.path_utils` helpers; do not bake absolute host paths into
  golden data or JSON fixtures.

## Fixtures

Fixtures are inputs to tests, not outputs of test runs.

- Fixture policy and layout: `book/integration/tests/ghidra/fixtures/README.md`.
