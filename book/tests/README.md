# Testing in `book/`

We use pytest-based sanity checks across examples, validation utilities, and experiment artifacts. These tests are meant to catch import/path regressions and obvious structural issues; they are not full behavioral coverage of sandbox semantics.

## Running tests

- Single entrypoint: `make -C book test` (pytest + Swift build). This is the only supported runner.
- Direct pytest (local/dev): `PYTHONPATH=$(pwd) python -m pytest` from the repo root.
- Use `-m system` to include/exclude system-dependent tests.

## Structure (planes)

- `book/tests/planes/smoke`: import/sanity checks for core modules.
- `book/tests/planes/examples`: example demos + experiment output checks.
- `book/tests/planes/contracts`: SBPL/profile/decoder contracts and CLI checks.
- `book/tests/planes/graph`: vocab, concepts, mappings, anchors, field2, validation guardrails.
- `book/tests/planes/carton`: CARTON indices/coverage/query API and manifest checks.
- `book/tests/planes/ghidra`: Ghidra outputs, kernel scans, shape catalog guardrails.
- `book/tests/planes/runtime`: runtime matrices, promotion packets, lifecycle, hardened runtime.
- `book/tests/planes/tools`: preflight/gate minimizer/trace shrink/frida/entitlement tooling.

## Artifacts and logs

- Test artifacts live under `book/tests/out/` and are cleared on each run.
  - `run.json`: run metadata (world_id, python, platform).
  - `summary.json`: totals + exit status.
  - per-test directories: `report.json`, `failure.txt` on failures, and `stdout.txt`/`stderr.txt`/`command.json` when `run_cmd` is used.

## Notes for contributors

- Use the `run_cmd` fixture for subprocess calls so outputs are captured into artifacts.
- Keep tests fast and deterministic; avoid long-running or networked steps.
- Mark anything that shells out or depends on macOS/Apple libs as `@pytest.mark.system`.
- Assert paths as repo-relative strings using `book.api.path_utils` helpers.
- Update fixture hashes when binaries change (see `book/graph/concepts/validation/fixtures/fixtures.json`).
