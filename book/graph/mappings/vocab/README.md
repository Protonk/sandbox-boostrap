# Vocabulary mappings

Stable Operation and Filter vocabulary artifacts harvested from the host dyld cache (Sonoma).

These files instantiate the **Operation Vocabulary Map** and **Filter Vocabulary Map** from Concepts: they connect SBPL names (e.g., `file-read*`, `mach-lookup`, `path`, `global-name`) to the numeric IDs used in compiled PolicyGraphs. All higher-level decoding and capability catalogs rely on these IDs being stable and versioned.

Contents:
- `ops.json` / `filters.json` – Primary Operation/Filter vocab maps (ID ↔ name plus provenance). These are the authoritative operation/filter ID tables for this host/build.
- `operation_names.json` / `filter_names.json` – Raw harvested name lists from `libsandbox`; useful for sanity checks and future vocab extractions.

Source: harvested from `book/evidence/graph/mappings/dyld-libs/usr/lib/libsandbox.1.dylib` for this host baseline (see `book/graph/mappings/vocab/generate_vocab_from_dyld.py`). Treat these files as read-only, versioned mappings for this host when interpreting compiled profiles, op-tables, and anchor/field2 results.
