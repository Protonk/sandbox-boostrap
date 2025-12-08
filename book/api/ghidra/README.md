# Ghidra connector (book/api/ghidra)

Role: stable, host-specific connector for running Seatbelt-focused Ghidra headless tasks. This is the canonical scaffold; `dumps/ghidra/scaffold.py` is now a shim.

Baseline and safety:
- Host: see `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5 (baseline: book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json)`.
- Inputs live in `dumps/Sandbox-private/<build>/...` (KC, libsystem_sandbox, profiles); never copy them into tracked trees.
- Outputs stay under `dumps/ghidra/out/<build>/<task>/`; projects under `dumps/ghidra/projects/`; user/temp under `dumps/ghidra/user` and `dumps/ghidra/tmp` (git-ignored).
- `HOME`/`GHIDRA_USER_HOME` and `JAVA_TOOL_OPTIONS=-Duser.home=... -Djava.io.tmpdir=...` are set to the sandboxed dirs to avoid leakage or prompts.

Interfaces:
- Python API: `TaskRegistry` + `HeadlessConnector` (build/run headless commands with consistent env).
- CLI scaffold: `python -m book.api.ghidra.scaffold <task> [--build-id ...] [--exec] ...`. The shim `python dumps/ghidra/scaffold.py ...` still works.
- Convenience runner: `python book/api/ghidra/run_task.py <task> --exec` (defaults: ARM64 processor, x86 analyzers disabled via pre-script).
- Scripts live in `book/api/ghidra/scripts/`; `dumps/ghidra/scripts/` are redirectors only.

Tasks (examples; see `TaskRegistry.default()` for the full set):
- `kernel-symbols` (fast, `--no-analysis` OK): dump sandbox symbols/strings; outputs also mirrored to `book/experiments/kernel-symbols/out/<build>/...`.
- `kernel-tag-switch` (needs full analysis): heuristic ranking of computed-jump functions to find the PolicyGraph dispatcher; output `dumps/ghidra/out/<build>/kernel-tag-switch/switch_candidates.json`.
- `kernel-op-table`, `kernel-string-refs`, `kernel-imm-search`, `kernel-field2-mask-scan`: various scans over the KC for op-table candidates, strings/imports, immediates, and field2-like masks.
- `kernel-data-define`: define data at `addr:<hex>` targets and dump refs; use `--process-existing --no-analysis` after a full analysis pass.

Tag-switch triage (rolled up from the former `dumps/ghidra/Tag_triage.md`):
- Run with full analysis (no `--no-analysis`) so functions/computed jumps exist.
- Inspect `switch_candidates.json`, sort by `computed_jumps` then `size`, and skim the top ~20; filter to sandbox.kext address ranges if noise is high.
- Outputs and decompile batches live under `dumps/ghidra/out/<build>/kernel-tag-switch/` and `.../tag-triage/` (when produced); manual review in project `dumps/ghidra/projects/sandbox_<build>`.

Analyzer and processor notes:
- `analyzeHeadless` 11.4.2 ignores `-analysisProperties`; use pre-scripts. `disable_x86_analyzers.py` is provided; pass `--pre-script disable_x86_analyzers.py`.
- Set an explicit processor for the KC (e.g., `--processor AARCH64:LE:64:AppleSilicon`) to avoid x86 auto-detection and x86 analyzers.

Usage sketch (dry-run):
```python
from book.api.ghidra import connector

runner = connector.HeadlessConnector(registry=connector.TaskRegistry.default(), ghidra_headless="/path/to/analyzeHeadless")
inv = runner.build(task_name="kernel-symbols", build_id="14.4.1-23E224", no_analysis=True)
print(inv.render_shell())
```

Execution (when Ghidra is available):
```python
result = runner.run(inv, execute=True)
print(result.returncode, result.out_dir)
```

### Node struct/evaluator tooling

Reusable helpers live in `book/api/ghidra/ghidra_lib/node_scan_utils.py` (expr handling, index/base inference, load filtering, usage tagging; JSON schema_version is `1.0`). Scripts can import this module via the path bootstrap included at the top of each script.

To scan for “small struct” patterns under `_eval` (default addr fffffe000b40d698) in `BootKernelCollection.kc`:

```bash
export JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home
export JAVA_TOOL_OPTIONS="-Dapplication.settingsdir=$PWD/.ghidra-user -Duser.home=$PWD/dumps/ghidra/user"
export HOME="$PWD/dumps/ghidra/home"
export GHIDRA_USER_HOME="$PWD/dumps/ghidra/user"
/opt/homebrew/opt/ghidra/libexec/support/analyzeHeadless \
  dumps/ghidra/tmp field2_eval_tmp \
  -process BootKernelCollection.kc \
  -noanalysis \
  -scriptPath book/api/ghidra/scripts \
  -postScript kernel_node_struct_scan.py scan dumps/ghidra/out/14.4.1-23E224/find-field2-evaluator
```

Outputs: `.../node_struct_scan.txt` and `.../node_struct_scan.json` (includes schema_version, eval_entry, functions_scanned, candidates). Adjust the eval address or process binary as needed.

Related notes:
- Troubleshooting and mitigations: `troubles/ghidra_setup.md` (now points back here for commands/env).
