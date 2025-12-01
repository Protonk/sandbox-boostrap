# Ghidra headless setup notes (11.4.2 on macOS 14.4.1-23E224)

Context: headless runs against `dumps/Sandbox-private/14.4.1-23E224/` via `dumps/ghidra/scaffold.py`. This log captures the friction points and the mitigations applied.

## Issues encountered
- **JDK prompt blocking headless**: `analyzeHeadless` attempted to prompt for a JDK path (uses `~/Library/ghidra/.../java_home.save`), failing with “Unable to prompt user for JDK path, no TTY detected.”
- **Path permission on host `java_home.save`**: the default `~` pointed to `/Users/achyland/Library/ghidra/ghidra_11.4.2_PUBLIC/java_home.save`, which is protected by seatbelt; writes from headless failed.
- **HOME leakage**: without overriding `HOME`/`GHIDRA_USER_HOME`, Ghidra would try to read/write in the real user tree, risking leaks and permissions errors.
- **Long analysis times**: full analysis of the KC was slow/noisy (lots of analysis warnings); for bootstrap runs we only needed import + script, not full analysis.
- **Script output silent initially**: no `scriptlog` emitted by default, making it hard to confirm script execution. Early stubs also had TypeErrors (API mismatches) that were invisible without inspecting `application.log`.
- **Signed-pointer interpretation**: raw pointer reads in the KC can be negative; initial pointer-table scan tried to feed unsigned values to `getAddress` and crashed.
- **Functionless tag-switch search**: when running with `-noanalysis`, functions are not recovered, so computed-jump counting returned zero candidates.

## Mitigations applied
- **Force Java selection non-interactively**: run headless with `--java-home /Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home` and pass `-vmPath .../bin/java`. Scaffold exports `JAVA_HOME` and injects `JAVA_TOOL_OPTIONS=-Duser.home=<repo>/dumps/ghidra/user` so LaunchSupport finds a writable home and skips prompting.
- **Sandbox Ghidra user dir**: `--user-dir dumps/ghidra/user` (default in scaffold) plus env `HOME`/`GHIDRA_USER_HOME` set to that path. Added `.gitignore` entry for `user/`.
- **Script logging**: scaffold now adds `-scriptlog <out>/<task>/script.log` so script stdout/stderr is captured per task.
- **Overwrite conflicting projects**: added `-overwrite` to avoid “conflicting program file” errors on repeated imports.
- **Optional `-noanalysis` flag**: exposed `--no-analysis` to speed up import-only passes when function recovery is not needed (used for symbols/strings; not suitable for dispatcher search).
- **Adjusted Jython scripts**:
  - `kernel_symbols.py`: avoid `getSymbolIterator(addr_set, True)` (API mismatch), filter manually, use `data.getValue()` for strings, add trace/error logs, guard against double-run.
  - `kernel_op_table.py`: sign-extend pointer values before `getAddress`; add error logging and run guard.
  - `kernel_tag_switch.py`: add error logging, run guard; note that it needs functions present (skip `--no-analysis` if you want candidates).

## Current working recipe
- Env: `GHIDRA_HEADLESS=/opt/homebrew/opt/ghidra/libexec/support/analyzeHeadless`, `JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home`.
- Command examples:
  - Symbols/strings (fast): `python3 dumps/ghidra/scaffold.py kernel-symbols --java-home $JAVA_HOME --no-analysis --exec`
  - Pointer tables: `python3 dumps/ghidra/scaffold.py kernel-op-table --java-home $JAVA_HOME --no-analysis --exec`
  - Tag switch (needs functions): drop `--no-analysis` for a slower but populated run.
- Outputs land under `dumps/ghidra/out/14.4.1-23E224/<task>/`; project at `dumps/ghidra/projects/sandbox_14.4.1-23E224`; user config at `dumps/ghidra/user/`.

## Remaining cautions
- Running without `--java-home` will still trigger the JDK prompt and fail under headless/non-TTY.
- `-noanalysis` suppresses function recovery; use it only when you don’t need call graphs or instruction walks.
- KC imports produce many analysis warnings; these are expected but keep an eye on `application.log` for script exceptions.
- Keep all runs contained in `dumps/`; do not relocate artifacts into tracked trees.
