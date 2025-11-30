# Vocab from Cache – Research Report (Sonoma / macOS 14.4.1)

## Purpose

Extract Operation/Filter vocab tables (name ↔ ID) from the macOS dyld shared cache (Sandbox.framework/libsandbox payloads) and align them with decoder-derived op_count/op_table data from canonical blobs, producing real `ops.json` / `filters.json` for this host.

## Scope and baseline

- Host: macOS 14.4.1 (23E224), kernel 23.4.0, arm64, SIP enabled.
- Canonical blobs for alignment:
- `book/examples/extract_sbs/build/profiles/airlock.sb.bin`
- `book/examples/extract_sbs/build/profiles/bsd.sb.bin`
- `book/examples/sb/build/sample.sb.bin`
- Current vocab artifacts (`graph/mappings/vocab/ops.json` / `filters.json`) are `status: ok` (196 ops, 93 filters) harvested from the dyld cache.

## Plan (summary)

1. Extract Sandbox-related binaries from the dyld shared cache.
2. Harvest operation/filter name tables from the extracted binaries.
3. Align harvested names with decoder op_count/op_table from canonical blobs; emit real vocab artifacts.
4. Rerun op-table alignment to fill operation IDs and record bucket↔ID relationships.

## Current status

- Dyld shared cache located at `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e`; extracted via Swift shim using `/usr/lib/dsc_extractor.bundle` into `book/experiments/vocab-from-cache/extracted/` (Sandbox.framework + libsandbox pulled out).
- Added `harvest_ops.py` to decode `_operation_names` → `__TEXT.__cstring`; harvested 196 ordered operation names (`out/operation_names.json`), confirming the op_count heuristic (167) was a decoder artifact.
- Added `harvest_filters.py` to decode `_filter_info` → `__TEXT.__cstring`; harvested 93 ordered filter names (`out/filter_names.json`).
- `book/graph/mappings/vocab/ops.json` is `status: ok` (IDs 0–195); `filters.json` now `status: ok` (IDs 0–92) from the cache harvest.
- Regenerated `book/experiments/op-table-operation/out/*` with the vocab length override (196 ops) and refreshed `op-table-vocab-alignment` to fill `operation_ids` per profile; op_table entries now cover the full vocabulary. (Filters not yet propagated into downstream experiments.)
- Added `check_vocab.py`, a guardrail script that asserts vocab status is `ok` and counts are ops=196, filters=93 for this host.
- Experiment marked complete; raw cache extraction under `book/experiments/vocab-from-cache/extracted/` removed after harvesting, with trimmed copies retained in `book/graph/mappings/dyld-libs/`.
