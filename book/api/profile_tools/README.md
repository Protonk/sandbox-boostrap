# profile_tools

Unified API/CLI for SBPL compilation, compiled-blob ingestion/decoding, inspection, op-table summaries, digests, and structural oracles on the Sonoma Seatbelt baseline.

- **CLI:** `python -m book.api.profile_tools.cli <compile|decode|inspect|op-table|digest|oracle> ...`
- **CLI (preferred):** `python -m book.api.profile_tools <compile|decode|inspect|op-table|digest|oracle> ...`
- **Python (preferred):** import submodules from `book.api.profile_tools` (`compile`, `ingestion`, `decoder`, `inspect`, `op_table`, `digests`, `oracles`) and call functions on those modules.
- **C (reference):** `make -C book/api/profile_tools/c` builds `build/compile_profile` (SBPL file → compiled blob via `sandbox_compile_file`).
- **Parameterized SBPL (compile-time):** `python -m book.api.profile_tools compile <profile.sb> --param ROOT=/private/tmp` (repeatable `--param KEY=VALUE`; see `profile_tools/libsandbox.py` for the params-handle interface).
- **Operational preflight (apply-gate signature):** `python3 book/tools/preflight/preflight.py scan <profile.sb> ...` flags deny-style `apply-message-filter` constructs that are currently apply-gated for the harness identity on this world (see `troubles/EPERMx2.md` and `book/experiments/gate-witnesses/Report.md` for witnesses).

See `book/api/README.md` for routing and deprecation notes.

## Routing

Pick the most direct tool for the job:

- **Compile:** `book/api/profile_tools/compile.py` – SBPL → compiled blob (`.sb.bin`) via libsandbox’s private compiler entry points.
- **Ingest (slice):** `book/api/profile_tools/ingestion.py` – header parse + section slicing (use `slice_sections_with_offsets` when you need explicit bounds).
- **Decode:** `book/api/profile_tools/decoder.py` – structural decode of modern blobs (heuristic; consumes tag-layout + vocab mappings when present).
- **Inspect:** `book/api/profile_tools/inspect.py` – read-only summaries for humans/guardrails (built from ingestion + decoder).
- **Op-table:** `book/api/profile_tools/op_table.py` – op-table centric summaries and vocab alignment helpers.
- **Digest:** `book/api/profile_tools/digests.py` – stable “digest” JSONs derived from the decoder (system-profile-digest and similar).
- **Oracles:** `book/api/profile_tools/oracles/` – structural “argument shape” extractors with explicit witnesses (e.g. network tuple).
- **Scan (engine):** `book/api/profile_tools/sbpl_scan.py` – conservative SBPL-only scanners for operational constraints (used by `book/tools/preflight`).
