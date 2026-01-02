# Examples — op-coverage-and-runtime-signatures (archived)

Canonical mapping:

- `book/evidence/graph/mappings/runtime/op_runtime_summary.json`

## Meta excerpt

```json
{
  "world_id": "sonoma-14.4.1-23E224-arm64-dyld-2c0602c5",
  "status": "ok",
  "tier": "mapped"
}
```

## Operation excerpt (`file-read*`)

```json
{
  "op_name": "file-read*",
  "blocked": {
    "total": 2,
    "by_stage": { "preflight": 2 },
    "by_kind": { "preflight_apply_gate_signature": 2 }
  }
}
```

## Regeneration

- Promote runtime mappings: `python3 book/graph/mappings/runtime/promote_from_packets.py`

