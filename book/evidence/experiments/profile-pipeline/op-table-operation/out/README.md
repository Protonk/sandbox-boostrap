# Outputs

Artifacts produced by `book/evidence/experiments/profile-pipeline/op-table-operation/analyze.py` (and its helper `build_catalog.py`). These are fixtures for `book/tests/planes/examples/test_experiments.py` and other guardrails:

- `summary.json` — per-variant op-table and node summaries (decoder blocks included).
- `op_table_map.json` / `op_table_signatures.json` — entrypoint mappings and traversal signatures.
- `op_table_catalog_v1.json` — catalogued op-table hints harvested from the variants.
- `runtime_signatures.json` — small runtime probe results tied to the same variants.

Regenerate by running `analyze.py`; tests expect these shapes but do not enforce specific values.***
