# AGENTS — `book/dumps/`

Purpose: hold host-specific artifacts and runtime outputs for the Sonoma baseline. Private inputs live under
`book/dumps/ghidra/private/` (git-ignored). This is not a staging area for new code or docs—park tooling and
writeups under `book/` (see below).

What lives here:
- `ghidra/private/aapl-restricted/<build>/` — extracted host artifacts (kernel KC, libsystem_sandbox, SBPL templates/compiled profiles, SYSTEM_VERSION.txt). **Do not copy these into tracked trees.**
- `ghidra/private/oversize/` — oversized extraction artifacts that must remain private.
- `ghidra/` — runtime workspace (out/projects/user/tmp/home/logs). Scripts and scaffold are canonical in `book/api/ghidra/`; this tree is footprints-only.

Routing:
- Need headless Ghidra tasks or scripts? Go to `book/api/ghidra/` (scaffold, connector, scripts, README). Run via `python -m book.api.ghidra.scaffold ...` or `python book/api/ghidra/run_task.py ...`.
- Need analysis outputs? They should land under `book/evidence/dumps/ghidra/out/` and projects under `book/dumps/ghidra/projects/`.

Rules:
- Do **not** check in new code, docs, or tooling here. Keep tracked sources under `book/` (including `book/substrate/`); use `book/dumps/` only for artifacts and runtime outputs.
- Keep artifacts contained: work in place under `book/dumps/` and never move `aapl-restricted` contents into tracked paths.
