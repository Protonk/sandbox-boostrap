# preflight-index notes

- Created experiment scaffold (Plan/Report/Notes).
- Implemented `build_index.py` and ran:
  - `python3 book/experiments/preflight-index/build_index.py`
  - Wrote `out/preflight_enterability_manifest.json` and `out/summary.json`.
- Added a guardrail test: `book/tests/test_preflight_index_manifest.py`.
- Expanded the SBPL inventory to include `book/experiments/**/*.sb` (excluding `out/`) and `book/examples/**/*.sb`, then regenerated `out/*.json` via `python3 book/experiments/preflight-index/build_index.py`.
