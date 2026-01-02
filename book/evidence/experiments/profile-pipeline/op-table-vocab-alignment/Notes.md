10. **mach-lookup ID interpretation (2025-12-08)**
    - External evidence (sbtool-style operation_names[], Mazurek’s Sonoma sandbox validator, Apple entitlements) supports a single `mach-lookup` op ID (96) with namespace splits expressed via filters (`GLOBAL_NAME`, `LOCAL_NAME`, `XPC_SERVICE_NAME`), not multiple mach-lookup operation IDs.
    - The observed bucket mix {5,6} in op-table-operation should be treated as filter-driven structural differences in compiled graphs, not as evidence of multiple mach-lookup IDs. Alignment will continue to model mach-lookup as a single op with filters carrying the namespace semantics.

## Updated

- Updated: refreshed `out/op_table_vocab_alignment.json` via `update_alignment.py` after correcting the op-table experiment’s framing (no “vocab-length op_count override”, stride=8 decoder witnesses captured upstream).
- Updated: treat “op-table slot index == Operation ID” as an unsupported assumption for the synthetic profiles in `op-table-operation` (their op-table lengths are small and per-profile); this experiment now uses vocab only to attach numeric IDs to the SBPL `ops` set, while keeping bucket claims keyed on the observed `op_entries` patterns.

## Migration

- Updated: alignment regeneration now runs via `book/tools/sbpl/op_table_runner.py`.
