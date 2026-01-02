# Outputs

Artifacts produced by `book/tools/sbpl/op_table_runner.py`. These are fixtures for `book/integration/tests/examples/test_experiments.py` and other guardrails:

- `summary.json` — per-variant op-table and node summaries (decoder blocks included).
- `op_table_map.json` / `op_table_signatures.json` — entrypoint mappings and traversal signatures.
- `op_table_catalog_v1.json` — catalogued op-table hints harvested from the variants.
- `runtime_signatures.json` — small runtime probe results tied to the same variants.

Regenerate by running `python3 book/tools/sbpl/op_table_runner.py`; tests expect these shapes but do not enforce specific values.
