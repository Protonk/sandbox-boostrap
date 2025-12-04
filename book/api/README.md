# API Tooling (Sonoma baseline)

This directory is the shared toolbox for the sandbox textbook. It collects small, composable helpers for:

- compiling SBPL into compiled profiles,
- decoding and inspecting compiled blobs,
- analysing op-tables and node structure,
- driving selected runtime experiments,
- and exporting artifacts for external tools (e.g. Ghidra, Graphviz).

All code here assumes the fixed host baseline recorded in `book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json` and the vocab/format mappings under `book/graph/mappings/`.

## Modules and when to use them

- `decoder/`
  - Role: Turn compiled sandbox blobs into structured dictionaries (format variant, op_table, nodes, literal pool, tag counts, etc.).
  - Use when: you need a programmatic view of a profile’s PolicyGraph for analysis or experiments.
  - Notes: honours the Operation/Filter vocabularies and tag-layout mappings; see `decoder/README.md` for field names.

- `sbpl_compile/`
  - Role: Wrap private `libsandbox` compile entry points.
  - Surfaces:
    - Python: `compile_sbpl_file(Path, Path|None)` and `compile_sbpl_string(str)`.
    - CLI: `python -m book.api.sbpl_compile.cli input.sb --out output.sb.bin`.
    - C: `c/compile_profile.c` as a minimal parity check.
  - Use when: you need ground-truth compiled blobs from SBPL for experiments or decoder tests.

- `inspect_profile/`
  - Role: Provide a quick, read-only snapshot of a compiled blob.
  - Output (see `Summary` dataclass): format variant, op_count, section lengths, op_entries, stride/tag stats, literal string runs, and a decoder echo.
  - Surfaces:
    - Python: `summarize_blob(bytes)` for direct integration.
    - CLI: `python -m book.api.inspect_profile.cli <blob|sb> [--compile] [--json OUT]`.
  - Use when: you want to understand a single blob’s shape before doing deeper graph or tag-layout work.

- `op_table/`
  - Role: Focused analysis of the op-table and per-entry structure.
  - Capabilities:
    - Parse `(allow ...)` ops and filter symbols from SBPL.
    - Compute op-table entries, per-entry signatures (tags + field2-like literals), tag counts, literal previews.
    - Optionally align entries to the Operation/Filter vocabularies (`ops.json`, `filters.json`).
  - Surfaces:
    - Python: `parse_ops`, `parse_filters`, `summarize_profile`, `entry_signature`, `build_alignment`.
    - CLI: `python -m book.api.op_table.cli <sb|blob> [--compile] [--op-count N] [--vocab ops.json --filters filters.json] [--json OUT]`.
  - Use when: extending or consuming the `op-table-operation` / `op-table-vocab-alignment` experiments, or when you need bucket-level fingerprints for profiles.

- `regex_tools/`
  - Role: Deal with legacy AppleMatch regex blobs from early decision-tree profile formats.
  - Surfaces:
    - `extract_legacy.py`: extract `.re` blobs from legacy `.sb.bin` files.
    - `re_to_dot.py`: convert compiled `.re` into Graphviz `.dot`.
  - Use when: working with historical Blazakis-era profiles or legacy tooling; modern graph-based profiles should go through `decoder` instead.

- `SBPL-wrapper/`
  - Role: Apply SBPL or compiled blobs to a process (e.g., for runtime-checks, sbpl-graph-runtime).
  - Notes:
    - Wraps `sandbox_init` / `sandbox_apply` and related plumbing.
    - On this host, apply gates and missing entitlements often surface as `EPERM`; experiments must treat those as `blocked`, not silently ignore them.
  - Use when: you need a controlled runtime harness rather than bare `sandbox-exec`.

- `file_probe/`
  - Role: Minimal JSON-emitting read/write probe binary to pair with `SBPL-wrapper`.
  - Use when: you want a deterministic file access target for sandbox allow/deny checks.

- `ghidra/`
  - Role: Provide hooks for Seatbelt-focused Ghidra analysis (kernel/op-table symbol work).
  - Use when: driving reverse-engineering tasks under `dumps/` or the kernel/entitlement experiments.
  - Notes: canonical scaffold/CLI lives here; `dumps/ghidra/` remains the runtime workspace plus a compatibility shim.

See `AGENTS.md` for a concise router view.

## Quick usage (CLI examples)

Run these from the repo root so relative paths and imports resolve correctly.

- Compile SBPL to a blob:

  ```sh
  python -m book.api.sbpl_compile.cli book/examples/sb/sample.sb --out /tmp/sample.sb.bin
  ```

- Inspect a blob (or SBPL with `--compile`):

  ```sh
  python -m book.api.inspect_profile.cli /tmp/sample.sb.bin --json /tmp/summary.json
  python -m book.api.inspect_profile.cli book/examples/sb/sample.sb --compile
  ```

- Op-table summary with vocab alignment:

  ```sh
  python -m book.api.op_table.cli book/experiments/op-table-operation/sb/v1_read.sb \
    --compile --op-count 196 \
    --vocab book/graph/mappings/vocab/ops.json \
    --filters book/graph/mappings/vocab/filters.json \
    --json /tmp/op_summary.json
  ```

- Legacy regex extraction/visualization:

  ```sh
  python -m book.api.regex_tools.extract_legacy legacy.sb.bin out/
  python -m book.api.regex_tools.re_to_dot out/legacy.sb.bin.000.re -o out/re.dot
  ```

## Host assumptions and invariants

- Baseline: see `book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json`.
- `libsandbox.dylib` is present and usable on this host (for `sbpl_compile` and runtime helpers).
- Operation/Filter vocabularies come from `book/graph/mappings/vocab/{ops,filters}.json` with `status: ok`.
- Tools here are **static-first**: they lean on decoded headers, op-tables, and vocab mappings; anything about runtime behaviour must flow through experiments and carry validation status (`ok`, `partial`, `brittle`, `blocked`).

## Tests and guardrails

- System-marked tests (require this host’s libsandbox and filesystem layout):
  - `book/tests/test_sbpl_compile_api.py` – sbpl_compile API/CLI smoke.
  - `book/tests/test_op_table_api.py` – op_table CLI smoke and alignment builder check.
- Pure-Python helpers:
  - `book/tests/test_regex_tools.py` – legacy regex parsing and `.re` → `.dot` behavior.
  - Decoder-focused tests under `book/tests/test_decoder_*` and `test_validation.py`.

When adding new API modules here, mirror this pattern:

- keep them small and host-specific,
- wire them to existing mappings/validation where possible,
- and add at least a minimal guard exercised via `make -C book test`.
