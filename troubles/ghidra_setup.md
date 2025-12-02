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
- **Full-analysis timeout**: a headless full-analysis run on BootKernelExtensions.kc timed out after 40 minutes (2400s) with analysis still in progress; heavy analysis and script runtime compete for the same wallclock.
- **Data-define post-script processed 0 targets**: `kernel_data_define_and_refs.py` ignored inputs when passed `0x-...` signed addresses or bare hex without the `addr:` prefix, so no data was defined even though analysis finished.
- **x86 analyzers running on ARM64 KC**: default analyzer set included `x86 Constant Reference Analyzer`, burning ~5 minutes on an ARM64 kernelcache with no useful output.

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
- **Long analysis mitigation**: split heavy runs into two phases—first run `analyzeHeadless` with a generous timeout and no postScript to populate functions/xrefs, then run a short postScript-only pass against the analyzed project to avoid timing out while analysis and script compete.
- **Data-define input format**: for `kernel-data-define`, feed targets as `addr:<unsigned hex>` (for example, `addr:0xffffff800020ef10`). Using `0x-...` or dropping the prefix yields zero processed targets. Use `--process-existing --no-analysis` to run the script against an already analyzed project.
- **Disable x86 analyzers**: add `-analysisProperties book/api/ghidra/analysis_arm64.properties` (sets `Analysis.X86 Constant Reference Analyzer.enabled=false` and `Analysis.X86 Emulate Instruction Analyzer.enabled=false`; escape spaces if you inline the string) to skip x86-only passes on ARM64 images.

## Current working recipe
- Env: `GHIDRA_HEADLESS=/opt/homebrew/opt/ghidra/libexec/support/analyzeHeadless`, `JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home`.
- Command examples:
- Symbols/strings (fast): `python3 dumps/ghidra/scaffold.py kernel-symbols --java-home $JAVA_HOME --no-analysis --exec`
- Pointer tables: `python3 dumps/ghidra/scaffold.py kernel-op-table --java-home $JAVA_HOME --no-analysis --exec`
- Tag switch (needs functions): drop `--no-analysis` for a slower but populated run.
- Data define (script-only against existing project): `PYTHONPATH=$PWD GHIDRA_HEADLESS=$GHIDRA_HEADLESS JAVA_HOME=$JAVA_HOME python3 book/api/ghidra/run_data_define.py --address addr:0xffffff800020ef10 --process-existing --no-analysis --timeout 900`
- Full analysis with x86 analyzers disabled: add `--analysis-properties book/api/ghidra/analysis_arm64.properties` to the scaffold invocation (import or process) to trim ~5 minutes on ARM64 kernelcaches.
- Outputs land under `dumps/ghidra/out/14.4.1-23E224/<task>/`; project at `dumps/ghidra/projects/sandbox_14.4.1-23E224`; user config at `dumps/ghidra/user/`.

## Remaining cautions
- Running without `--java-home` will still trigger the JDK prompt and fail under headless/non-TTY.
- `-noanalysis` suppresses function recovery; use it only when you don’t need call graphs or instruction walks.
- KC imports produce many analysis warnings; these are expected but keep an eye on `application.log` for script exceptions.
- Keep all runs contained in `dumps/`; do not relocate artifacts into tracked trees.
