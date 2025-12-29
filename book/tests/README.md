# Testing in `book/`

We use lightweight sanity checks across the examples, validation utilities, and experiment artifacts. These tests are meant to catch import/path regressions and obvious structural issues; they are not full behavioral coverage of sandbox semantics.

## Running tests

- Single entrypoint: `make -C book test` (Python harness + Swift build). This is the only supported runner.
  - This run includes the Ghidra shape checks, the strict-gate, and the canonical sentinel.

## Structure

- `test_smoke.py`: import/sanity checks for core modules.
- `test_examples.py`: wraps example demos (compile sample profiles, extract system profiles) and asserts outputs exist. Marks system-dependent tests.
- `test_validation.py`: structural checks using curated fixtures (op_table length, section sizes) via the validation decoder/fixtures.
- `test_experiments.py`: sanity checks over experiment outputs (e.g., JSON artifacts exist and contain expected keys).
- `test_op_table_api.py`: op_table CLI/system smoke plus alignment builder unit check.

## Notes for contributors

- `book/tests/run_all.py` mirrors pytest collection without invoking pytest. It still requires the `pytest` package for fixtures like `monkeypatch` but does not use pytest’s test runner.
- Keep tests fast and deterministic; avoid long-running or networked steps.
- Mark any test that shells out or depends on macOS/Apple libs as `@pytest.mark.system`.
- If adding new example/utility tests, prefer calling underlying Python helpers rather than shelling out when feasible.
- Update fixture hashes when binaries change (see `book/graph/concepts/validation/fixtures/fixtures.json`).
- On this host, the CI harness currently runs under `python@3.14` (see `ci.py`); if you see `pytest is required to import tests` when running `make -C book test`, install `pytest` into the Python 3.14 environment used by `book/tests/run_all.py`.***
