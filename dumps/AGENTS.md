# AGENTS — `dumps/`

Purpose: hold host-specific, git-ignored artifacts (`Sandbox-private/*`) for the Sonoma baseline. This is not a staging area for new code or docs—park tooling and writeups under `book/` (see below).

What lives here:
- `Sandbox-private/14.4.1-23E224/` — extracted host artifacts (kernel KC, libsystem_sandbox, SBPL templates/compiled profiles, SYSTEM_VERSION.txt). **Do not copy these into tracked trees.**
- `ghidra/` — runtime workspace only (out/projects/user/temp). Scripts and scaffold are canonical in `book/api/ghidra/`; this tree keeps a shim and redirectors so existing commands keep working.
- `RE_Plan.md` — historical context for the extraction effort; keep for reference, not as an active plan.

Routing:
- Need headless Ghidra tasks or scripts? Go to `book/api/ghidra/` (scaffold, connector, scripts, README). Run via `python -m book.api.ghidra.scaffold ...` or `python book/api/ghidra/run_task.py ...`; `dumps/ghidra/scaffold.py` remains a thin shim only.
- Need analysis outputs? They should land under `dumps/ghidra/out/` (git-ignored) and projects under `dumps/ghidra/projects/`.

Rules:
- Do **not** check in new code, docs, or tooling here. Keep tracked sources under `book/` (including `book/substrate/`); use `dumps/` only for git-ignored artifacts and runtime outputs.
- Keep artifacts contained: work in place under `dumps/`, prefer git-ignored subdirs, and never move `Sandbox-private` contents into tracked paths.
