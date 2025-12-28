# ghidra_lib helpers

Reusable utilities for Seatbelt-focused Ghidra headless scripts live here. They are importable via the path bootstrap at the top of scripts in `book/api/ghidra/scripts/`.

## node_scan_utils.py (schema_version 1.0)

Provides:
- `Expr` – lightweight linear expression wrapper used to represent load addresses.
- `collect_loads(func, program)` – collect LOAD pcodes with inferred expressions and widths.
- `choose_index_and_base(load_records)` – heuristic inference of index register, stride, and base register.
- `filter_loads(load_records, base_reg, index_reg, stride)` – keep loads that look like base+scaled-index+const.
- `analyze_usage(func, loads)` – tag instructions that bit-test/mask/shift or index-extend registers loaded from the struct.
- `block_name(func)` – memory block name for a function.
- `validate_candidate_schema(cand)` – minimal sanity check for candidate dicts.
- `SCHEMA_VERSION` – current JSON schema version for scan outputs.

Expected JSON schema (v1.0) for struct scans:
```json
{
  "schema_version": "1.0",
  "eval_entry": "fffffe000b40d698",
  "functions_scanned": 1234,
  "candidates": [
    {
      "function": "FUN_...",
      "entry": "fffffe00...",
      "block": "__text",
      "index_reg": "X22",
      "stride": 1,
      "base_reg": "X8",
      "byte_offsets": [0, 0xc5],
      "half_offsets": [0x1, 0xc3],
      "loads": [
        {"offset": 0, "width": 1, "dest": "W10", "mnemonic": "ldrb", "disasm": "..."}
      ],
      "usage": [
        {"insn": "fffffe00...", "disasm": "tbnz ...", "reg": "W10", "flags": ["tbnz"]}
      ],
      "instruction_count": 200
    }
  ]
}
```

Consumers should check `schema_version` before parsing and can use `validate_candidate_schema` as a minimal guard. Always include the schema/version field when emitting JSON from new scripts.

## scan_utils.py

Shared parsing helpers used by scan scripts:
- `parse_address` / `format_address` – canonicalize signed hex addresses.
- `exact_offset_match` – match `#0xc0` without false positives (`#0xc00`).
- `is_stack_access` – basic stack-frame access detection (`sp`/`x29`/`fp`).
- `classify_mnemonic` – lightweight load/store/other classification.
