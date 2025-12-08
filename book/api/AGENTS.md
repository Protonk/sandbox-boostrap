# Agents in `book/api/`

This directory is the API/tooling layer for the Seatbelt textbook. All tools assume the fixed host baseline in `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5 (baseline: book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json)` and the vocab/format mappings under `book/graph/mappings/`.

## How to route here

- `carton/` – Public CARTON query surface and manifest (`book/api/carton/CARTON.json`).
  - Read `book/api/carton/README.md` for CARTON’s role and concepts, `AGENTS.md` for routing/working rules, and `API.md` for function contracts.
  - Use `book.api.carton.carton_query` for stable facts about operations, filters, system profiles/profile layers, and runtime signatures. Handle `UnknownOperationError` (unknown op) vs `CartonDataError` (manifest/hash/mapping drift).
  - First moves: `list_operations`, `list_profiles`, `list_filters`, then `operation_story`, `profile_story`, `filter_story`, `runtime_signature_info`, `ops_with_low_coverage`.

- `decoder/` – Decode compiled sandbox blobs into structured Python dicts (format variant, op_table, nodes, literals, tag counts). See `decoder/README.md`.
- `sbpl_compile/` – Compile SBPL to compiled blobs (Python/CLI/C parity). See `sbpl_compile/README.md`.
- `inspect_profile/` – Quick structural snapshot of a compiled blob (format, counts, tag stats, literals). See `inspect_profile/README.md`.
- `op_table/` – Op-table parsing and vocab alignment helpers for `(allow ...)` ops and filter symbols. See `op_table/README.md`.
- `regex_tools/` – Legacy AppleMatch helpers for historical decision-tree profiles (`extract_legacy.py`, `re_to_dot.py`).
- `SBPL-wrapper/` – Runtime harness for applying SBPL/compiled blobs; treats `EPERM` apply gates as `blocked` on this host.
- `file_probe/` – Minimal JSON-emitting read/write probe to pair with SBPL-wrapper.
- `runtime_golden/` – Helpers for runtime-checks “golden” profiles (compile/decode, normalize runtime_results).
- `golden_runner/` – Harness for running expectation-driven “golden triple” probes (emits runtime_results.json).
- `ghidra/` – Seatbelt-focused Ghidra scaffold/CLI for kernel/op-table symbol work; see `ghidra/README.md` for workspace norms.

## Expectations

- Stay within the host baseline and substrate vocabulary; lean on `book/graph/mappings/` for vocab and format truths.
- Prefer CARTON for concept-level questions (ops ↔ profiles ↔ runtime signatures); do not re-parse validation outputs when CARTON already exposes the concept.
- Use the validation driver and promotion pipeline when changing mappings that feed CARTON; do not hand-edit files listed in `book/api/carton/CARTON.json`.
- Keep tools small, host-specific, and backed by minimal guards run via `make -C book test`.
