# runtime tests (taxonomy)

This repo runs tests via `make -C book test` (the `book/tests/run_all.py` harness). The runtime surface now spans both legacy matrix-based mapping checks and the newer runtime bundle service.

This document classifies the runtime tests by purpose so they stay discriminating and avoid overlapping coverage.

## Unit tests

Pure-function or small-object checks. No subprocesses, no launchd, and minimal filesystem interaction.

- `book/tests/test_runtime_tools_unit_plan_digest.py`
- `book/tests/test_runtime_tools_unit_public_api.py` (public export surface guard)

## Component tests

Exercise one subsystem boundary (artifact IO, promotion packet emission, repair tooling, harness integration) using `tmp_path` and monkeypatching. No launchd required.

- `book/tests/test_runtime_tools_component_preflight.py` (harness preflight integration)
- `book/tests/test_runtime_tools_component_promotion_packet.py` (promotability rules + strict emission)
- `book/tests/test_runtime_tools_component_reindex_bundle.py` (digest mismatch + repair workflow)

## Service tests

Exercise the high-level `run_plan()` bundle lifecycle and its reliability invariants (run-scoped layout, lock semantics, commit barrier ordering, pointer updates) in `dry_run` mode with failure injection.

- `book/tests/test_runtime_tools_service_bundle.py`
