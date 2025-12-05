# AGENTS.md — book/api router

You are in `book/api/`, the API/tooling layer for the Seatbelt textbook. This file is a map, not a workflow script: it tells you **where** to look for a given job.

- `README.md`
  - Summary of current API surfaces, host assumptions, and quick commands.
  - Read this first if you are new to `book/api/`.

- `decoder/`
  - Role: decode compiled sandbox blobs into structured Python objects (headers, op_table, nodes, literal pool).
  - Use when: you need to reason about PolicyGraphs or build higher-level analyses without re-parsing headers.

- `sbpl_compile/`
  - Role: compile SBPL into compiled profile blobs using `libsandbox` (Python API + CLI + small C demo).
  - Use when: you need `.sb.bin` inputs for decoder/experiments or want to regenerate example/experiment blobs.

- `inspect_profile/`
  - Role: quick, read-only inspection of a single compiled blob (section sizes, op-table entries, stride/tag stats, literals, decoder echo).
  - Use when: you want a structural snapshot of a profile before diving into tag layouts or op-table details.

- `op_table/`
  - Role: op-table–centric analysis (SBPL ops/filters parsing, entry signatures, vocab alignment).
  - Use when: extending or consuming `op-table-operation` / `op-table-vocab-alignment`, or when you need bucket-level fingerprints tied to vocab IDs.

- `regex_tools/`
  - Role: legacy AppleMatch helpers for decision-tree profile formats (`extract_legacy.py`, `re_to_dot.py`).
  - Use when: working with early-format profiles; modern graph-based profiles should go through `decoder`.

- `SBPL-wrapper/`
  - Role: apply SBPL or compiled blobs to a process for runtime experiments.
  - Use when: you need a controlled harness for `sandbox_init`/`sandbox_apply` (platform blobs may hit `EPERM` apply gates; treat those as `blocked`).

- `file_probe/`
  - Role: tiny read/write probe binary that emits JSON with `errno`.
  - Use when: you need a low-noise target process for runtime experiments driven by `SBPL-wrapper`.

- `ghidra/`
  - Role: connectors and scaffolding for Seatbelt-related Ghidra tasks (kernel/op-table symbol work).
  - Use when: driving reverse-engineering workflows under `dumps/` and kernel/entitlement experiments.
  - Notes: this is the canonical scaffold; `dumps/ghidra/` keeps the runtime workspace and a compatibility shim.

- `carton/`
  - Role: API surface for CARTON, the frozen IR/mapping set rooted at `book/graph/carton/CARTON.json`.
  - Use when: you want stable information about operations, system profiles, or runtime signatures. Prefer `book.api.carton.carton_query` over reading mapping JSONs by hand. Be ready to handle `UnknownOperationError` and `CartonDataError` if you probe for unknown ops or if CARTON data is missing/out of sync.

For vocabulary, lifecycle, and concept discipline, step up to `substrate/AGENTS.md`. All new tooling here should:

- target the fixed baseline from `book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json`,
- consume existing mappings and validation artifacts where possible,
- and publish enough structure that tests under `book/tests/` can keep it honest.
