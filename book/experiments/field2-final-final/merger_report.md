# Field2 Final Final — Merger Report

This report records what was consolidated into this experiment. All paths are repo-relative.

## Merged sources
- `book/experiments/field2-atlas/` -> `book/experiments/field2-final-final/field2-atlas/`
- `book/experiments/field2-filters/` -> `book/experiments/field2-final-final/field2-filters/`
- `book/experiments/probe-op-structure/` -> `book/experiments/field2-final-final/probe-op-structure/`
- `book/experiments/anchor-filter-map/` -> `book/experiments/field2-final-final/anchor-filter-map/`
- `book/experiments/libsandbox-encoder/` -> `book/experiments/field2-final-final/libsandbox-encoder/`
- `book/experiments/flow-divert-2560/` -> `book/experiments/field2-final-final/flow-divert-2560/`
- `book/experiments/bsd-airlock-highvals/` -> `book/experiments/field2-final-final/bsd-airlock-highvals/`

## Retained experiments stripped of field2 content
- `book/experiments/node-layout/`
- `book/experiments/op-table-operation/`
- `book/experiments/op-table-vocab-alignment/`
- `book/experiments/runtime-final-final/suites/metadata-runner/`
- `book/experiments/runtime-final-final/suites/vfs-canonicalization/`

## Additional relocations
- `book/experiments/runtime-final-final/suites/metadata-runner/check_structural.py` -> `book/experiments/field2-final-final/metadata-runner/check_structural.py`
- `book/experiments/runtime-final-final/suites/metadata-runner/out/anchor_structural_check.json` -> `book/experiments/field2-final-final/metadata-runner/out/anchor_structural_check.json`

## Archive targets
The original experiment directories listed above are moved under `book/experiments/archive/` after migration.
