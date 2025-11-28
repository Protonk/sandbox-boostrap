# Vocab from Cache – Research Report (Sonoma / macOS 14.4.1)

## Purpose

Extract Operation/Filter vocab tables (name ↔ ID) from the macOS dyld shared cache (Sandbox.framework/libsandbox payloads) and align them with decoder-derived op_count/op_table data from canonical blobs, producing real `ops.json` / `filters.json` for this host.

## Scope and baseline

- Host: macOS 14.4.1 (23E224), kernel 23.4.0, arm64, SIP enabled.
- Canonical blobs for alignment:
  - `book/examples/extract_sbs/build/profiles/airlock.sb.bin`
  - `book/examples/extract_sbs/build/profiles/bsd.sb.bin`
  - `book/examples/sb/build/sample.sb.bin`
- Current vocab artifacts (`validation/out/vocab/ops.json` / `filters.json`) are `status: partial` with decoder-derived op_count/op_table metadata only.

## Plan (summary)

1. Extract Sandbox-related binaries from the dyld shared cache.
2. Harvest operation/filter name tables from the extracted binaries.
3. Align harvested names with decoder op_count/op_table from canonical blobs; emit real vocab artifacts.
4. Rerun op-table alignment to fill operation IDs and record bucket↔ID relationships.

## Current status

- Experiment initialized; plan and notes created. Extraction/harvesting not yet performed.
