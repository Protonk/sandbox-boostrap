# Agents in `book/api/`

This directory is the API/tooling layer for the Seatbelt textbook. All tools assume the fixed host baseline in `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5` and the vocab/format mappings under `book/graph/mappings/`.

## How to route here

- `carton/` – Public CARTON query surface and manifest (`book/api/carton/CARTON.json`).
  - Read `book/api/carton/README.md` for CARTON’s role and concepts, `AGENTS.md` for routing/working rules, and `API.md` for function contracts.
  - Use `book.api.carton.carton_query` for stable facts about operations, filters, system profiles/profile layers, and runtime signatures. Handle `UnknownOperationError` (unknown op) vs `CartonDataError` (manifest/hash/mapping drift).
  - First moves: `list_operations`, `list_profiles`, `list_filters`, then `operation_story`, `profile_story`, `filter_story`, `runtime_signature_info`, `ops_with_low_coverage`.

- `profile_tools/` – Unified surface for SBPL compilation, blob decoding/inspection, op-table summaries, and structural oracles (replaces `sbpl_compile`, `inspect_profile`, `op_table`, and the former standalone `decoder`/`sbpl_oracle` modules).
- `SBPL-wrapper/` – Runtime harness for applying SBPL/compiled blobs; treats `EPERM` apply gates as `blocked` on this host.
- `file_probe/` – Minimal JSON-emitting read/write probe to pair with SBPL-wrapper.
- `runtime_harness/` – Unified runtime generation + probe runner (replaces `runtime_golden` and `golden_runner` shims).
- `ghidra/` – Seatbelt-focused Ghidra scaffold/CLI for kernel/op-table symbol work; see `ghidra/README.md` for workspace norms.

## Expectations

- Stay within the host baseline and substrate vocabulary; lean on `book/graph/mappings/` for vocab and format truths.
- Prefer CARTON for concept-level questions (ops ↔ profiles ↔ runtime signatures); do not re-parse validation outputs when CARTON already exposes the concept.
- Use the validation driver and promotion pipeline when changing mappings that feed CARTON; do not hand-edit files listed in `book/api/carton/CARTON.json`.
- Keep tools small, host-specific, and backed by minimal guards run via `make -C book test`.
