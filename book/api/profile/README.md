# profile

Unified profile-byte tooling for the Sonoma baseline (`world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`).

This package is intentionally **structural**:
- It compiles SBPL into compiled profile blobs and inspects/decodes the resulting bytes.
- It does not define sandbox semantics; use runtime evidence (`book/api/runtime/`) and the CARTON contract bundle (`book/integration/carton/`) for concept-shaped answers.
- Apply-stage failures (`sandbox_apply` / `EPERM`) are not denials; use preflight (`book/tools/preflight`) before live runtime probes.

## Public API (stable surface)

This README defines the supported public surface for `book.api.profile`.

Supported import surface:
- Import **from a surface package** (recommended):
  - `from book.api.profile.compile import compile_sbpl_file`
  - `from book.api.profile.decoder import decode_profile_dict`
  - `from book.api.profile.ingestion import slice_sections_with_offsets`
- Import the namespace only to reach surfaces (discouraged for callables):
  - `import book.api.profile as pt` then `pt.compile`, `pt.decoder`, …

Callers should treat **only** the symbols exported in each surface package’s `__all__` as stable.

Surfaces:
- `book.api.profile.compile`: SBPL → compiled blob via libsandbox’s private compiler entry points (supports compile-time params; see `book/api/profile/compile/README.md`).
- `book.api.profile.ingestion`: header parsing + section slicing (`op_table`, `nodes`, `regex_literals`) with explicit offsets (see `book/api/profile/ingestion/README.md`).
- `book.api.profile.decoder`: best-effort structural decoder for modern graph-based blobs (heuristic, mapping-assisted when available; see `book/api/profile/decoder/README.md`).
- `book.api.profile.inspect`: read-only summaries for humans/guardrails (built on ingestion + decoder).
- `book.api.profile.op_table`: op-table-centric summaries + SBPL token hints + vocab alignment helpers.
- `book.api.profile.digests`: stable, decoder-backed digests for curated blobs (notably canonical system profiles).
- `book.api.profile.identity`: mapping join surface for canonical system profile ids ↔ blob paths ↔ sha256 ↔ attestations.
- `book.api.profile.sbpl_scan`: conservative SBPL-only scanners for operational constraints (used by `book/tools/preflight`; see `book/api/profile/sbpl_scan/README.md`).
- `book.api.profile.oracles`: structural “argument shape” extractors with byte-level witnesses (see `book/api/profile/oracles/README.md`).

Low-level reference:
- `book/tools/sbpl/compile_profile/`: minimal C reference compiler (`sandbox_compile_file` → `.sb.bin`); Python is canonical.

## CLI (stable surface)

Canonical entrypoint:

```sh
python -m book.api.profile ...
```

Supported commands (stable flags and JSON output shapes):
- `compile <paths...> [--out PATH | --out-dir DIR] [--param KEY=VALUE] [--params-json PATH] [--no-preview]`
- `decode dump <blobs...> [--bytes N] [--node-stride 8|12|16] [--summary] [--out PATH]`
- `inspect <path> [--compile] [--stride 8 12 16] [--out PATH]`
- `op-table <path> [--compile] [--op-count N] [--vocab ops.json] [--filters filters.json] [--out PATH]`
- `digest system-profiles [--out PATH]`
- `oracle network-blob --blob PATH [--out PATH]`

Examples:
```sh
# Compile SBPL to a blob.
python -m book.api.profile compile book/examples/sb/sample.sb --out /tmp/sample.sb.bin

# Compile with compile-time params for `(param "ROOT")`.
python -m book.api.profile compile book/examples/sb/sample.sb \
  --param ROOT=/private/tmp \
  --out /tmp/sample.sb.bin

# Decode a blob header + section boundaries (machine output).
python -m book.api.profile decode dump /tmp/sample.sb.bin --summary

# Human inspection (machine output).
python -m book.api.profile inspect /tmp/sample.sb.bin --out /tmp/summary.json
```

## Dataflow (where profile fits)

`profile` sits upstream of the validation → mappings → CARTON pipeline:
1. Compile SBPL (`compile/`) and slice/decode compiled blobs (`ingestion/`, `decoder/`).
2. Normalize structural outputs into validation IR (`book/graph/concepts/validation/out/…`).
3. Generate host mappings from validation IR (`book/graph/mappings/**`).
4. Refresh CARTON’s manifest-verified contract set (`python -m book.integration.carton.tools.update`).

If you are trying to answer “what does this operation/filter mean?”, prefer CARTON. If you are trying to answer “what bytes did libsandbox emit for this SBPL input on this host?”, use `profile`.

## Guardrails and boundaries

- **Contract-bypass discipline:** this package compiles SBPL (`sandbox_compile_*`) but does not provide apply/run (`sandbox_init`, `sandbox_apply`) surfaces; runtime apply/probe flows live under `book/api/runtime/`.
- **Apply-gate discipline:** SBPL shapes that compile but cannot apply for the harness identity are expected on this world; run `book/tools/preflight` to avoid dead-end runtime probes.
- **Repo-relative paths:** when emitting paths in JSON, use `book.api.path_utils.to_repo_relative` helpers (callers and tools should not embed absolute paths in checked-in artifacts).

See also:
- `book/api/README.md` (router)
- `book/tools/preflight/README.md` (apply-gate avoidance)
- `book/api/profile/compile/README.md`
- `book/api/profile/ingestion/README.md`
- `book/api/profile/decoder/README.md`
- `book/api/profile/sbpl_scan/README.md`
- `book/api/profile/oracles/README.md`
