"""
Helper to run the `kernel-data-define` task via the connector.

Use when: you want a small wrapper that enforces the correct address format and reuses the connector defaults.

Inputs/outputs:
- Inputs come from `book/dumps/ghidra/private/aapl-restricted/<build>/...` (KC imported into the project).
- Outputs land under `book/dumps/ghidra/out/<build>/kernel-data-define/` (data_refs.json, script log).

Address format:
- Pass targets as `addr:<unsigned hex>` (e.g., `addr:0xffffff800020ef10`). Signed `0x-...` or bare hex will process 0 targets.

Example (script-only pass against existing project):
  GHIDRA_HEADLESS=/opt/homebrew/opt/ghidra/libexec/support/analyzeHeadless \\
  JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home \\
  PYTHONPATH=$PWD \\
  python3 book/api/ghidra/run_data_define.py \\
    --address addr:0xffffff800020ef10 \\
    --process-existing --no-analysis --timeout 900
"""

from __future__ import annotations

import argparse
import os

from book.api.ghidra import connector
from book.api.ghidra import scaffold


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run kernel-data-define via HeadlessConnector.")
    # Use addr: prefix to avoid Ghidra's signed-hex ambiguity in headless scripts.
    parser.add_argument("--address", required=True, help="Address to define (e.g., 0x-7fffdf10f0).")
    parser.add_argument("--build", default=scaffold.DEFAULT_BUILD_ID, help="aapl-restricted build ID.")
    parser.add_argument("--task-name", default="kernel-data-define", help="Ghidra task name.")
    parser.add_argument("--no-analysis", action="store_true", help="Pass -noanalysis to headless.")
    parser.add_argument(
        "--process-existing", action="store_true", help="Run against existing project via -process (no overwrite)."
    )
    parser.add_argument("--project-name", help="Optional project name (defaults to sandbox_<build>).")
    parser.add_argument("--timeout", type=int, default=None, help="Subprocess timeout in seconds.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    java_home = os.environ.get("JAVA_HOME")
    headless_bin = os.environ.get("GHIDRA_HEADLESS")

    runner = connector.HeadlessConnector(ghidra_headless=headless_bin, java_home=java_home)
    script_args = [args.address]
    invocation = runner.build(
        task_name=args.task_name,
        build_id=args.build,
        project_name=args.project_name,
        no_analysis=args.no_analysis,
        process_existing=args.process_existing,
        script_args=script_args,
    )
    # Print the command to support copy/paste runs in troubleshooting sessions.
    print("Command:", invocation.render_shell())
    result = runner.run(invocation, execute=True, timeout=args.timeout)
    print("Return code:", result.returncode)
    print("Output dir:", invocation.out_dir)
    return 0 if result.returncode == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
