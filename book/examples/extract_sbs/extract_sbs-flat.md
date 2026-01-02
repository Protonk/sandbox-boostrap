## extract_sbs (docs-only)

This directory is **docs-only**.

The original runnable compiler script has been superseded by `book/api/profile`.

Canonical compiled blobs (tracked for this host baseline):
- `book/evidence/graph/concepts/validation/fixtures/blobs/airlock.sb.bin`
- `book/evidence/graph/concepts/validation/fixtures/blobs/bsd.sb.bin`

---

## Regenerate the canonical blobs

From the repo root:

```sh
python -m book.api.profile compile \
  /System/Library/Sandbox/Profiles/airlock.sb \
  /System/Library/Sandbox/Profiles/bsd.sb \
  --out-dir book/evidence/graph/concepts/validation/fixtures/blobs \
  --no-preview
```

---

## Decode / inspect

```sh
python -m book.api.profile decode dump book/evidence/graph/concepts/validation/fixtures/blobs/airlock.sb.bin --summary
python -m book.api.profile decode dump book/evidence/graph/concepts/validation/fixtures/blobs/bsd.sb.bin --summary
```

---

## Notes

- These blobs are used as canonical decoder/mapping inputs on this host baseline; if you regenerate them, also refresh the affected IR/mappings via `make -C book test`.
