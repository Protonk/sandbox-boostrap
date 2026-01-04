# Agents in `book/api/`

This directory is the API/tooling layer for the Seatbelt textbook. All tools assume the fixed host baseline in `world_id sonoma-14.4.1-23E224-arm64-dyld-a3a840f9` and the vocab/format mappings under `book/integration/carton/bundle/relationships/mappings/` (generators live under `book/integration/carton/mappings/`).

## How to route here

- CARTON lives under `book/integration/carton/` as an integration fixer bundle (relationships, views, contracts, manifest, and tools); there is no CARTON API surface in `book/api/`.
- `profile/` – Canonical surface for profile-byte work: SBPL compilation, blob decoding/inspection, op-table summaries, digests, and structural oracles (replaces `sbpl_compile`, `inspect_profile`, `op_table`, and the former standalone `decoder`/`sbpl_oracle` modules).
  - Legacy packages (`book.api.sbpl_compile`, `book.api.inspect_profile`, `book.api.op_table`) have been removed; route callers here.
- `runtime/` – Unified runtime observations + mappings + harness runner/generator (replaces `runtime` + `runtime_harness`).
  - Native helpers live under `runtime/native/`, including `native/file_probe/` (minimal JSON-emitting read/write probe).
- `ghidra/` – Seatbelt-focused Ghidra scaffold/CLI for kernel/op-table symbol work; see `ghidra/README.md` for workspace norms.

## Expectations

- Stay within the host baseline and substrate vocabulary; lean on `book/integration/carton/bundle/relationships/mappings/` for vocab and format truths.
- CARTON is the integration fixer bundle; prefer its frozen relationships/views/contracts instead of re-parsing validation outputs ad hoc.
- Use the validation driver and promotion pipeline when changing mappings that feed CARTON; do not hand-edit files listed in `book/integration/carton/bundle/CARTON.json`.
- Keep tools small, host-specific, and backed by minimal guards run via `make -C book test`.
