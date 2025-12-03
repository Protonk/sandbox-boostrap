# Ghidra connector (book/api/ghidra)

Purpose: provide a stable, agent-friendly connector for running Seatbelt-focused Ghidra headless tasks from the textbook API layer. This wraps the existing `dumps/ghidra` scaffold and scripts without moving host artifacts out of `dumps/` and keeps all outputs in the same sandboxed tree.

Scope and constraints:
- Inputs come from `dumps/Sandbox-private/<build>/...` (kernel KC, libsystem_sandbox, profiles). The connector does not copy these into tracked trees.
- Scripts live under `book/api/ghidra/scripts/`; output and projects stay under `dumps/ghidra/out/` and `dumps/ghidra/projects/`.
- Default env pins `HOME`/`GHIDRA_USER_HOME` to `dumps/ghidra/user/` and exports `JAVA_TOOL_OPTIONS=-Duser.home=...` to avoid leaks into the real user home and to dodge macOS Seatbelt prompts.
- Temporary files are rooted at `dumps/ghidra/tmp/` via `TMPDIR`/`java.io.tmpdir`, with best-effort cleanup of `.lastmaint` cache markers after runs to avoid permission noise.

What this layer exposes:
- A `TaskRegistry` of Ghidra tasks (mirrors the current scaffold tasks: kernel symbols, tag switch triage, op-table scan, string refs, immediate search, etc.).
- A `HeadlessConnector` that builds and (optionally) runs `analyzeHeadless` commands with consistent env and logging, returning a structured invocation object (command, env, output dir, project name).
- Extensible task registration for future refactors: new scripts can be registered with a path, import target (kernel/userland), description, and defaults without changing callers.

Usage sketch (dry-run):
```python
from book.api.ghidra import connector

registry = connector.TaskRegistry.default()
runner = connector.HeadlessConnector(registry=registry)

inv = runner.build(
    task_name="kernel-symbols",
    build_id="14.4.1-23E224",
    no_analysis=True,
    script_args=[],
)
print(inv.render_shell())  # inspect the command without running
```

Execution (when Ghidra is available):
```python
result = runner.run(inv, execute=True)
print(result.returncode, result.out_dir)
```

Design notes:
- Scripts live here (`book/api/ghidra/scripts/`) and the `dumps/ghidra/scripts/` directory now only contains redirectors for compatibility; `-scriptPath` in the scaffold/connector points at this directory.
- This connector intentionally wraps the existing `dumps/ghidra/scaffold.py` helpers to avoid duplicating path rules and to keep safety checks (`ensure_under`, output layout) consistent.
- The connector is version-aware via `build_id` and accepts `project_name`, `processor`, and `process_existing` to reuse analyzed projects, mirroring the scaffold’s knobs.
- Future consolidation (single “ghidra-tool” front-end) can swap task scripts behind the registry entries without changing the agent-facing API in `book/api/ghidra`.

Addressing and script-only passes:
- The `kernel_data_define_and_refs.py` script expects each target as `addr:<hex>` using unsigned hex (for example, `addr:0xffffff800020ef10`). Passing `0x-...` or omitting the `addr:` prefix will result in “processed 0 targets.”
- To avoid repeating long analysis, run `--process-existing --no-analysis` once a project is fully analyzed; this skips analyzers and only executes the script against the saved project.
- Outputs for data-define land at `dumps/ghidra/out/<build>/kernel-data-define/data_refs.json` with the per-address data type/value and callers.
- `kernel_field2_mask_scan.py` searches sandbox code for mask immediates (defaults: 0x3fff, 0x4000, 0xc000) to surface potential filter_arg/field2 flag handling. Args: `<out_dir> <build_id> [mask_hex ...] [all]`.

Analyzer trimming and pre-scripts:
- `analyzeHeadless` 11.4.2 does not accept `-analysisProperties`; instead use a pre-script. A helper `disable_x86_analyzers.py` lives in `book/api/ghidra/scripts/`—run it via `--pre-script disable_x86_analyzers.py` (scaffold/connector) to turn off the x86-only analyzers before analysis begins.
- For Apple Silicon KC imports, explicitly set the processor (for example, `--processor AARCH64:LE:64:AppleSilicon` if available in your Ghidra build) to avoid x86-language auto-detection and keep x86 analyzers from running. The `run_task.py` helper defaults to this processor and adds the disable-x86 pre-script unless you opt out.

Convenience runner:
- `book/api/ghidra/run_task.py` wraps `HeadlessConnector` with repo defaults (ARM64 processor + disable_x86 pre-script). Example:
  ```
  GHIDRA_HEADLESS=/opt/homebrew/opt/ghidra/libexec/support/analyzeHeadless \
  JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home \
  PYTHONPATH=$PWD \
  python3 book/api/ghidra/run_task.py kernel-symbols --exec
  ```
  Use `--process-existing --no-analysis` to reuse an analyzed project, `--no-pre-scripts` to skip the x86-disabling helper, and `--pre-script`/`--processor` to override defaults.

Outputs:
- Most tasks write under `dumps/ghidra/out/<build>/<task>/`. The `kernel-symbols` task is routed to the experiment tree at `book/experiments/kernel-symbols/out/<build>/kernel-symbols/` to keep symbol/string outputs co-located with notes.
