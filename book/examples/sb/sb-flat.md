## sb (docs-only)

This directory is **docs-only**.

- SBPL source lives here (`sample.sb`, `variant1.sb`).
- Compilation, decoding, and inspection are provided by `book/api/profile/`.

Canonical compiled blob (tracked for this host baseline):
- `book/graph/concepts/validation/fixtures/blobs/sample.sb.bin`

---

## Regenerate the canonical blob

From the repo root:

```sh
python -m book.api.profile compile book/examples/sb/sample.sb \
  --out book/graph/concepts/validation/fixtures/blobs/sample.sb.bin \
  --no-preview
```

---

## Decode / inspect

```sh
python -m book.api.profile inspect book/graph/concepts/validation/fixtures/blobs/sample.sb.bin
python -m book.api.profile decode dump book/graph/concepts/validation/fixtures/blobs/sample.sb.bin --summary
```

---

## Notes

- The compiled blob is consumed by validation and mapping generators; if you regenerate it, refresh the affected IR/mappings via `make -C book test`.
