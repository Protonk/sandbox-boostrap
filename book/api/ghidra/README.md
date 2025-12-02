# Ghidra connector (book/api/ghidra)

Purpose: provide a stable, agent-friendly connector for running Seatbelt-focused Ghidra headless tasks from the textbook API layer. This wraps the existing `dumps/ghidra` scaffold and scripts without moving host artifacts out of `dumps/` and keeps all outputs in the same sandboxed tree.

Scope and constraints:
- Inputs come from `dumps/Sandbox-private/<build>/...` (kernel KC, libsystem_sandbox, profiles). The connector does not copy these into tracked trees.
- Scripts live under `dumps/ghidra/scripts/`; output and projects stay under `dumps/ghidra/out/` and `dumps/ghidra/projects/`.
- Default env pins `HOME`/`GHIDRA_USER_HOME` to `dumps/ghidra/user/` and exports `JAVA_TOOL_OPTIONS=-Duser.home=...` to avoid leaks into the real user home and to dodge macOS Seatbelt prompts.

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
- This connector intentionally wraps the existing `dumps/ghidra/scaffold.py` helpers to avoid duplicating path rules and to keep safety checks (`ensure_under`, output layout) consistent.
- The connector is version-aware via `build_id` and accepts `project_name`, `processor`, and `process_existing` to reuse analyzed projects, mirroring the scaffold’s knobs.
- Future consolidation (single “ghidra-tool” front-end) can swap task scripts behind the registry entries without changing the agent-facing API in `book/api/ghidra`.
