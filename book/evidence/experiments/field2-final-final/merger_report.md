# Field2 Final Final — Merger Report

This report records what was consolidated into this experiment. All paths are repo-relative.

## Merged sources
- `book/evidence/experiments/field2-atlas/` -> `book/evidence/experiments/field2-final-final/field2-atlas/`
- `book/evidence/experiments/field2-filters/` -> `book/evidence/experiments/field2-final-final/field2-filters/`
- `book/evidence/experiments/runtime-final-final/suites/field2-probe-op-structure/` -> `book/evidence/experiments/field2-final-final/probe-op-structure/`
- `book/evidence/experiments/runtime-final-final/suites/anchor-filter-map/` -> `book/evidence/experiments/field2-final-final/anchor-filter-map/`
- `book/evidence/experiments/libsandbox-encoder/` -> `book/evidence/experiments/field2-final-final/libsandbox-encoder/`
- `book/evidence/experiments/flow-divert-2560/` -> `book/evidence/experiments/field2-final-final/flow-divert-2560/`
- `book/evidence/experiments/bsd-airlock-highvals/` -> `book/evidence/experiments/field2-final-final/bsd-airlock-highvals/`

## Retained experiments stripped of field2 content
- `book/evidence/experiments/profile-pipeline/node-layout/`
- `book/evidence/experiments/profile-pipeline/op-table-operation/`
- `book/evidence/experiments/profile-pipeline/op-table-vocab-alignment/`
- `book/evidence/experiments/runtime-final-final/suites/metadata-runner/`
- `book/evidence/experiments/runtime-final-final/suites/vfs-canonicalization/`

## Additional relocations
- `book/evidence/experiments/runtime-final-final/suites/metadata-runner/check_structural.py` -> `book/evidence/experiments/field2-final-final/metadata-runner/check_structural.py`
- `book/evidence/experiments/runtime-final-final/suites/metadata-runner/out/anchor_structural_check.json` -> `book/evidence/experiments/field2-final-final/metadata-runner/out/anchor_structural_check.json`

## Archive targets
The original experiment directories listed above are moved under `book/evidence/experiments/archive/` after migration.
