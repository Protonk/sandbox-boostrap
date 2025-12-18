# Decoder Fixtures and Aids

This directory holds parser-independent assets to de-risk modern `.sb.bin` decoding:

- `fixtures.json` — curated blob list (paths, size, sha256, host metadata) for quick verification without parsing.
- `blobs/` — curated compiled `.sb.bin` blobs tracked in-repo for this host baseline.
- `hexdumps/` — first/last 64-byte snapshots for each fixture to anchor header/op-table/literal offsets.
- `generate_hexdumps.py` — helper to regenerate hexdumps from `fixtures.json` (uses repo-root resolution; comments inline).
- `INVARIANTS.md` — structural assertions a decoder should enforce (op-table length, edge bounds, printable tail, etc.).
- `FORMAT_NOTES.md` — quick cues for legacy vs modern variants and a fallback strategy for “unknown-modern” blobs.
- `VOCAB_CONTRACT_SAMPLE.json` — example schema for future `ops.json` / `filters.json` outputs (with metadata/versioning placeholders).
- `run_fixture_harness.py` — skeleton driver to load fixtures, call a decoder, and validate basic counts (to be completed once a decoder exists).

These assets are intended to keep decoder work focused and reproducible; they do not implement parsing themselves.***
