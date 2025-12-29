# Examples — system-profile-digest (archived)

Canonical mapping (BEDROCK_SURFACES `bedrock:canonical-system-profiles`):

- `book/graph/mappings/system_profiles/digests.json`

## Digest excerpt (`sys:bsd`)

```json
{
  "op_count": 28,
  "node_count": 69,
  "tag_counts": {
    "27": 26,
    "26": 13,
    "17": 1,
    "5": 1,
    "0": 26,
    "1": 2
  },
  "sections": {
    "op_table": 56,
    "nodes": 554,
    "literal_pool": 1514,
    "nodes_start": 72,
    "literal_start": 626
  }
}
```

## Regeneration

- Validation job: `python3 -m book.graph.concepts.validation --experiment system-profile-digest`
- Mapping generator: `python3 book/graph/mappings/system_profiles/generate_digests_from_ir.py`

