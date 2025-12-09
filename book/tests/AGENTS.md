# Agent Guidance for `book/tests/`

- Default harness: `make -C book test` (runs the pytest-free `book/tests/run_all.py` plus Swift build). This is the only supported entrypoint.
- These are **sanity checks**, not full behavioral tests. They catch import/path regressions and obvious structural issues; they do not validate sandbox semantics end-to-end.
- Mark anything that shells out or depends on macOS/Apple libs as `@pytest.mark.system`.
- Prefer calling underlying Python helpers over shell scripts when possible; keep tests fast/deterministic.
- When updating fixtures (e.g., compiled blobs), refresh hashes in `book/graph/concepts/validation/fixtures/fixtures.json` if tests depend on them.
- Assert paths as repo-relative strings. If a fixture or output includes repo files, normalize via `book.api.path_utils.to_repo_relative/relativize_command` rather than embedding `/Users/...` or `~/...` in assertions or golden data.
