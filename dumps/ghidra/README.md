# Ghidra headless scaffold (`dumps/ghidra/`)

Purpose: run repeatable, headless Ghidra jobs against the 14.4.1-23E224 artifacts in `dumps/Sandbox-private/`. Outputs stay under `dumps/ghidra/out/` and projects under `dumps/ghidra/projects/`; nothing leaves `dumps/`.

## Layout
- `scaffold.py` — command builder for headless runs; prints (or executes) `analyzeHeadless` invocations that import the KC or dylib and run task scripts.
- `scripts/` — Ghidra (Jython) stubs per task:
  - `kernel_symbols.py` — import KC and dump symbols/strings (JSON) scoped to com.apple.security.sandbox blocks.
  - `kernel_tag_switch.py` — rank functions by computed jumps to surface the PolicyGraph dispatcher/tag switch.
  - `kernel_op_table.py` — scan sandbox blocks for pointer-table candidates (op entrypoint table).
- `.gitignore` — ignores `out/`, `projects/`, and `user/` so runs stay untracked.

## Usage (dry-run by default)
```sh
# Show the command for kernel symbols/strings without running it
python3 dumps/ghidra/scaffold.py kernel-symbols --ghidra-headless /path/to/analyzeHeadless

# Execute (requires Ghidra installed and env input files present)
python3 dumps/ghidra/scaffold.py kernel-symbols --ghidra-headless /path/to/analyzeHeadless --exec
```

Arguments:
- `task`: one of `kernel-symbols`, `kernel-tag-switch`, `kernel-op-table`.
- `--build-id`: defaults to `14.4.1-23E224`.
- `--ghidra-headless`: path to `analyzeHeadless` (env `GHIDRA_HEADLESS` also honored).
- `--java-home`: exported to the subprocess (plus `JAVA_TOOL_OPTIONS=-Duser.home=...`) to avoid the interactive JDK prompt.
- `--vm-path`: explicit path to `java` to feed `-vmPath` (defaults to `JAVA_HOME/bin/java` when `--java-home` is set).
- `--user-dir`: user settings directory used for `HOME`/`GHIDRA_USER_HOME` during the run (default `dumps/ghidra/user` inside the repo sandbox).
- `--no-analysis`: add `-noanalysis` to the headless command for faster import-only runs.
- `--exec`: actually run; otherwise the tool prints a shell-ready command.

## Safety rules
- Inputs always come from `dumps/Sandbox-private/<build>/...`.
- Outputs always land in `dumps/ghidra/out/<build>/<task>/`; projects in `dumps/ghidra/projects/`.
- Commands add `-overwrite` and `-scriptlog` and set `HOME`/`GHIDRA_USER_HOME` to the repo-local `user/` dir to keep artifacts contained.
- Scripts live in `dumps/ghidra/scripts/`; do not move or copy host data into tracked trees.
