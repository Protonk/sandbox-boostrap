# preflight-index notes

- Archived: experiment-local wrapper scripts and `out/` snapshots were removed; the canonical builder is `book/tools/preflight/build_index.py` and the checked-in artifacts live under `book/tools/preflight/index/`.

- Created experiment scaffold (Plan/Report/Notes).
- Implemented `build_index.py` and ran:
  - `python3 book/tools/preflight/build_index.py`
  - Wrote `book/tools/preflight/index/preflight_enterability_manifest.json` and `book/tools/preflight/index/summary.json`.
- Added a guardrail test: `book/tests/test_preflight_index_manifest.py`.
- Expanded the SBPL inventory to include `book/evidence/experiments/**/*.sb` (excluding `out/`) and `book/tools/sbpl/corpus/**/*.sb`, then regenerated via `python3 book/tools/preflight/build_index.py`.

- Regenerated the manifest after new `gate-witnesses` compile-vs-apply artifacts landed:
  - `python3 book/tools/preflight/build_index.py`
- Regenerated again after the permissive (`--yolo`) gate-witnesses refresh:
  - `python3 book/tools/preflight/build_index.py`
- Regenerated after encoder-write-trace blobs expanded inventory coverage:
  - `python3 book/tools/preflight/build_index.py`
- Regenerated after adding vfs-canonicalization variant SBPLs:
  - `python3 book/tools/preflight/build_index.py`
- Regenerated after adding the vfs-canonicalization `/var/tmp` data-spelling profile:
  - `python3 book/tools/preflight/build_index.py`
- Canonical artifacts now live under `book/tools/preflight/index/`; this experiment’s `build_index.py` is a wrapper over the tool entrypoint.
