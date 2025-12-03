"""
Convenience runner for Ghidra tasks with sensible ARM64 defaults.

Defaults:
- Uses the disable_x86_analyzers pre-script to turn off x86-only analyzers.
- Sets the processor to an ARM64 language ID (overrideable).

Example (import + full analysis with defaults):
  GHIDRA_HEADLESS=/opt/homebrew/opt/ghidra/libexec/support/analyzeHeadless \
  JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home \
  PYTHONPATH=$PWD \
  python3 book/api/ghidra/run_task.py kernel-symbols --exec

Reuse existing analyzed project:
  python3 book/api/ghidra/run_task.py kernel-symbols --process-existing --no-analysis --exec
"""

from __future__ import annotations

import argparse
import os
from typing import List

from book.api.ghidra import connector

DEFAULT_PROCESSOR = "AARCH64:LE:64:AppleSilicon"
DEFAULT_PRE_SCRIPTS = ["disable_x86_analyzers.py"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a Ghidra task with repo defaults.")
    parser.add_argument("task", help="Task name (from connector registry).")
    parser.add_argument("--build", default=None, help="Build ID (defaults to scaffold default).")
    parser.add_argument("--project-name", help="Override project name (defaults to sandbox_<build>).")
    parser.add_argument("--ghidra-headless", help="Path to analyzeHeadless (env GHIDRA_HEADLESS fallback).")
    parser.add_argument("--java-home", help="JAVA_HOME to export for headless.")
    parser.add_argument("--vm-path", help="Override VM path passed via -vmPath.")
    parser.add_argument("--processor", default=DEFAULT_PROCESSOR, help="Processor/language ID (default ARM64).")
    parser.add_argument("--no-analysis", action="store_true", help="Add -noanalysis.")
    parser.add_argument("--process-existing", action="store_true", help="Use existing project via -process.")
    parser.add_argument(
        "--no-pre-scripts",
        action="store_true",
        help="Skip default pre-scripts (disable_x86_analyzers).",
    )
    parser.add_argument(
        "--pre-script",
        nargs="*",
        default=[],
        help="Additional pre-scripts to run before analysis (names on scriptPath).",
    )
    parser.add_argument("--script-args", nargs="*", default=[], help="Args passed to the Ghidra task script.")
    parser.add_argument("--timeout", type=int, default=None, help="Subprocess timeout in seconds.")
    parser.add_argument("--exec", action="store_true", dest="do_exec", help="Execute instead of printing.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    java_home = args.java_home or os.environ.get("JAVA_HOME")
    headless_bin = args.ghidra_headless or os.environ.get("GHIDRA_HEADLESS")

    pre_scripts: List[str] = []
    if not args.no_pre_scripts:
        pre_scripts.extend(DEFAULT_PRE_SCRIPTS)
    if args.pre_script:
        pre_scripts.extend(args.pre_script)

    runner = connector.HeadlessConnector(ghidra_headless=headless_bin, java_home=java_home)
    inv = runner.build(
        task_name=args.task,
        build_id=args.build,
        project_name=args.project_name,
        processor=args.processor,
        no_analysis=args.no_analysis,
        process_existing=args.process_existing,
        script_args=args.script_args,
        ghidra_headless=headless_bin,
        java_home=java_home,
        vm_path=args.vm_path,
        pre_scripts=pre_scripts,
    )
    print("Command:", inv.render_shell())
    if not args.do_exec:
        return 0
    result = runner.run(inv, execute=True, timeout=args.timeout)
    print("Return code:", result.returncode)
    print("Output dir:", inv.out_dir)
    return 0 if result.returncode == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
