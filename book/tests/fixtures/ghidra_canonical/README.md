# Ghidra canonical sentinel fixtures

These fixtures lock a single high-signal Ghidra output to guard freshness and
semantic stability for the Sonoma 14.4.1 baseline.

- `*.json` holds the normalized output used by the sentinel test.
- `*.meta.json` records provenance (schema version, script path + hash, input
  path + hash, Ghidra version, analysis profile, world_id, output path).

Promotion criteria:
- Add a new sentinel only when it covers a new failure mode (pipeline stage,
  normalization surface, or invariant class).

Dependency policy (current):
- Conservative root hashing: any `*.py` change under `book/api/ghidra/ghidra_lib/`
  (plus `ghidra_bootstrap.py`) invalidates the sentinel and requires regenerating
  the live output, then refreshing the fixture.
- If this becomes too noisy, bump the provenance schema and switch to an
  import-closure list or a curated depset for that sentinel.

Update workflow:
1. Re-run the underlying Ghidra task to refresh the output in `dumps/ghidra/out/`.
2. Refresh the canonical fixture + metadata:

```sh
python -m book.api.ghidra.refresh_canonical --name offset_inst_scan_0xc0_write_classify
```

All paths are repo-relative; do not embed absolute host paths in metadata.

Sentinel scope guardrail:
- Keep 1–3 canonical sentinels total.
- Add a new sentinel only when it protects a different failure mode than the existing one.
- Prefer small, deterministic outputs with internal-consistency invariants.
