# Examples — preflight-index (archived)

Canonical artifacts:

- Summary: `book/tools/preflight/index/summary.json`
- Manifest: `book/tools/preflight/index/preflight_enterability_manifest.json`

## Summary shape (excerpt)

```json
{
  "counts": {
    "total_records": 651,
    "by_classification": {
      "likely_apply_gated_for_harness_identity": 24,
      "no_known_apply_gate_signature": 627
    }
  }
}
```

## Manifest record shape (excerpt)

```json
{
  "path": "book/tools/sbpl/corpus/baseline/sample.sb",
  "preflight": {
    "input_kind": "sbpl_path",
    "classification": "no_known_apply_gate_signature",
    "signature": null
  },
  "sources": ["tools_sbpl"]
}
```

```json
{
  "path": "book/evidence/experiments/encoder-write-trace/out/blobs/gate_airlock_minimal_file.sb.bin",
  "preflight": {
    "input_kind": "sbpl_blob_path",
    "classification": "likely_apply_gated_for_harness_identity",
    "signature": "apply_gate_blob_digest"
  }
}
```

## Regeneration

- Builder: `python3 book/tools/preflight/build_index.py`
- Guardrail: `book/tests/test_preflight_index_manifest.py`
