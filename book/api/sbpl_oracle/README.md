# sbpl_oracle

Host-scoped “oracle” helpers that map SBPL-visible structure to compiled profile bytes for the fixed Sonoma baseline (`world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`).

This module is intentionally **structural**:
- Inputs are compiled profile blobs (and optionally SBPL sources via the compiler).
- Outputs are extracted values plus explicit byte-level witnesses (record offsets and record headers).
- It does **not** claim kernel semantics; it is a way to make SBPL↔blob structure falsifiable.

## Current surface

### Network tuple oracle (`domain`, `type`, `proto`)

`book.api.sbpl_oracle.network` implements an extractor for the socket argument tuple using only structural witnesses established by the `libsandbox-encoder` experiment’s network matrix corpus.

- Python:
  - `from book.api.sbpl_oracle.network import extract_network_tuple`
  - `result = extract_network_tuple(blob_bytes)`
  - `result.domain`, `result.type`, `result.proto`
  - `result.sources` and `result.conflicts` carry the byte-level witnesses.

- CLI (dataset runner; does not compile SBPL):
  - `python -m book.api.sbpl_oracle.cli network-matrix --manifest <MANIFEST.json> --blob-dir <dir> --out <out.json>`

The dataset output schema is recorded at `book/api/sbpl_oracle/schemas/network_matrix_oracle.v1.schema.json`.

## Relationship to experiments

The initial witness corpus and the first oracle implementation were developed under:
- `book/experiments/libsandbox-encoder/`

The experiment retains the SBPL specimens and compiled blobs as provenance and as a stable test corpus. The API oracle is the maintained surface for reuse across tooling and validation.

