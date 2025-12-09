# profile_tools

Unified API/CLI for SBPL compilation, compiled-blob inspection, and op-table summaries on the Sonoma Seatbelt baseline. This package is the new home for the former `sbpl_compile`, `inspect_profile`, and `op_table` helpers; those modules remain as shims.

- **CLI:** `python -m book.api.profile_tools.cli <compile|inspect|op-table> ...`
- **Python:** import from `book.api.profile_tools` for compilation (`compile_sbpl_*`), inspection (`summarize_blob`), and op-table summaries (`summarize_profile`).

See `book/api/README.md` for routing and deprecation notes.***
