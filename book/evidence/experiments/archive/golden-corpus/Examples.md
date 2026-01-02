# Examples — golden-corpus (archived)

Canonical artifacts (structural regression corpus; not runtime semantics):

- Manifest: `book/evidence/graph/concepts/validation/golden_corpus/corpus_manifest.json`
- Summary: `book/evidence/graph/concepts/validation/golden_corpus/corpus_summary.json`
- Validation job: `book/evidence/graph/concepts/validation/golden_corpus_job.py`

## Manifest excerpt

```json
{
  "world_id": "sonoma-14.4.1-23E224-arm64-dyld-2c0602c5",
  "tag_layouts_sha256": "65364b15910be5ec34aace92b8525838f286dce9deef734969434eeea180181a"
}
```

## Entry excerpt (static-only platform fixture)

```json
{
  "id": "platform_airlock",
  "category": "platform",
  "mode": "static-only",
  "compiled_path": "book/evidence/graph/concepts/validation/fixtures/blobs/airlock.sb.bin"
}
```

## Validation status excerpt

From `book/evidence/graph/concepts/validation/out/experiments/golden-corpus/status.json`:

```json
{
  "job_id": "experiment:golden-corpus",
  "status": "ok",
  "metrics": { "entries": 8, "mismatches": 0 }
}
```
