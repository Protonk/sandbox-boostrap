# AGENTS.md — book/api router

You are in `book/api/`, the API/tooling layer for the Seatbelt textbook. This file routes you to the right subcomponents; it is not a workflow script.

- `PLAN.md` — high-level API shape and resource model (sections, concepts, artifacts, catalogs). Read first to understand intended surfaces.
- `decoder/` — Python decoder package (`book.api.decoder`) for compiled sandbox profile blobs. See `decoder/README.md` for usage and JSON fields.
- `SBPL-wrapper/` — helper that applies SBPL text or compiled blobs to a process (`wrapper.c`, `README.md`, `extract_cache.sh`). Used by runtime experiments to exercise profiles.
- `ghidra/` — connector for Seatbelt-focused Ghidra headless tasks (wraps `dumps/ghidra` scripts with a registry and runner).

For vocabulary, lifecycle, and concept discipline, step up to `substrate/AGENTS.md`.
