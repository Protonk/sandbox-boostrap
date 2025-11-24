## 2025-11-23: profile-ingestion-layer-core

- **What changed**
  - Implemented `concepts/cross/profile-ingestion/ingestion.py` as a shared Profile Ingestion layer for the modern graph-based format.
  - Refactored `examples/sb/` to consume the shared ingestion parser for header/section parsing.
  - Added a smoke test in `concepts/cross/profile-ingestion/smoke/` that compiles and parses `examples/sb/` output.
- **Orientation vs reality**
  - Matches the Binary Profile Header and Operation Pointer Table concepts in `CONCEPT_INVENTORY.md` §3.10–3.11 and Axis 4.1 for the modern format produced by `sandbox_compile_*`.
  - Only modern graph-based blobs from `examples/sb/`/`examples/sbsnarf/` are supported; legacy decision-tree and bundled formats remain unhandled.
- **Modern behavior vs earlier assumptions**
  - Modern `sandbox_compile_file` outputs a small header + uint16 op-pointer table + fixed 8-byte node records, followed by a literal/regex section; counts and offsets are derived from header words and op-pointer maxima.
- **Confidence**
  - Smoke test compiles a real profile and parses it; `examples/sb/` behavior remains intact while exercising the shared layer.

## 2025-11-23: profile-ingestion-legacy-format

- **What changed**
  - Extended `concepts/cross/profile-ingestion/ingestion.py` to support a legacy/early decision-tree profile format (`legacy-tree-v1`) alongside the modern graph-based format.
  - Refactored `examples/sbdis/` to use the shared ingestion layer for header/section parsing while keeping local node/handler decoding.
  - Updated smoke tests to exercise both modern (`examples/sb/`) and synthetic legacy blobs via the shared ingestion API.
- **Orientation vs reality**
  - Confirms the Profile Format Variant concept (§3.15) across two concrete encodings; Binary Profile Header and Operation Pointer Table concepts (§3.10–3.11) now have shared coverage for both modern and early formats.
- **Confidence**
  - Both `examples/sb/` and `examples/sbdis/` run successfully using the shared ingestion layer; smoke tests parse both formats.
