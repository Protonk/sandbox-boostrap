# Examples — tag-layout-decode (archived)

Canonical mapping (BEDROCK_SURFACES `bedrock:modern-tag-layouts`):

- `book/graph/mappings/tag_layouts/tag_layouts.json`

## Metadata excerpt

```json
{
  "world_id": "sonoma-14.4.1-23E224-arm64-dyld-2c0602c5",
  "status": "ok",
  "tier": "bedrock"
}
```

## Tag entry excerpt

```json
{
  "tag": 0,
  "record_size_bytes": 8,
  "edge_fields": [0, 1],
  "payload_fields": [2]
}
```

## Regeneration

- Generator: `python3 book/graph/mappings/tag_layouts/generate_tag_layouts.py`
- Guardrail: `book/tests/test_mappings_guardrail.py`

