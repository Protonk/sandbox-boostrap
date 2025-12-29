# Examples — vocab-from-cache (archived)

Canonical mappings (BEDROCK_SURFACES `bedrock:operation-vocabulary`):

- `book/graph/mappings/vocab/ops.json`
- `book/graph/mappings/vocab/filters.json`

## Metadata excerpt (`ops.json`)

```json
{
  "world_id": "sonoma-14.4.1-23E224-arm64-dyld-2c0602c5",
  "status": "ok",
  "tier": "bedrock"
}
```

## Entry excerpts

```json
{
  "id": 0,
  "name": "default",
  "source": "book/graph/mappings/dyld-libs/usr/lib/libsandbox.1.dylib"
}
```

```json
{
  "id": 0,
  "name": "path",
  "source": "book/graph/mappings/dyld-libs/usr/lib/libsandbox.1.dylib"
}
```

## Regeneration

- Dyld inputs: `book/graph/mappings/dyld-libs/usr/lib/libsandbox.1.dylib`
- Generator: `python3 book/graph/mappings/vocab/generate_vocab_from_dyld.py`

