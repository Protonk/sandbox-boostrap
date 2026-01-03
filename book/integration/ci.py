#!/usr/bin/env python3
"""
Unified test/build driver for SANDBOX_LORE.

This is intentionally colocated with the test suite (`book/integration/`) so the
"how we run tests" harness lives next to the code it executes.

Supported entrypoints:
- `make -C book test` (invokes this module via `python -m book.integration.ci`)
- `python -m book.integration.ci field2_hunt` (field2-focused PASS_TO_PASS loop)

This driver runs:
1) pytest (Python guardrails)
2) Swift graph build (static enforcement + generator compile)
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

from book.api import path_utils


def _repo_root() -> Path:
    return path_utils.find_repo_root(Path(__file__))


def _book_root(repo_root: Path) -> Path:
    return repo_root / "book"


def run_python_harness() -> None:
    repo_root = _repo_root()
    env = os.environ.copy()
    env["PYTHONPATH"] = str(repo_root)

    cmd = [sys.executable, "-m", "pytest"]
    print(f"[ci] python-harness: running {' '.join(cmd)}", flush=True)
    subprocess.check_call(cmd, cwd=repo_root, env=env)


def run_carton_validation() -> None:
    repo_root = _repo_root()
    env = os.environ.copy()
    env["PYTHONPATH"] = str(repo_root)

    cmd = [sys.executable, "-m", "book.integration.carton", "build"]
    print(f"[ci] carton: running {' '.join(cmd)}", flush=True)
    subprocess.check_call(cmd, cwd=repo_root, env=env)


def run_swift_build() -> None:
    repo_root = _repo_root()
    book_root = _book_root(repo_root)
    graph_root = book_root / "integration" / "carton" / "graph"

    env = os.environ.copy()
    env["SWIFT_BIN"] = env.get("SWIFT", "swift")

    module_cache = graph_root / ".module-cache"
    module_cache.mkdir(parents=True, exist_ok=True)
    env.setdefault("CLANG_MODULE_CACHE_PATH", str(module_cache))
    env.setdefault("SWIFTPM_MODULECACHE_OVERRIDE", str(module_cache))

    cmd = [sys.executable, "swift_build.py"]
    print(f"[ci] swift-build: running {' '.join(cmd)}", flush=True)
    subprocess.check_call(cmd, cwd=graph_root, env=env)


def run_field2_hunt() -> None:
    repo_root = _repo_root()
    env = os.environ.copy()
    env["PYTHONPATH"] = str(repo_root)

    tests = [
        "book/integration/tests/graph/test_field2_atlas.py",
        "book/integration/tests/graph/test_field2_unknowns.py",
        "book/integration/tests/graph/test_field2_progress_gate.py",
        "book/integration/tests/graph/test_anchor_field2_alignment.py",
        "book/integration/tests/graph/test_anchor_filter_alignment.py",
        "book/integration/tests/graph/test_anchor_outputs.py",
        "book/integration/tests/graph/test_mappings_guardrail.py::test_field2_inventory_present",
        "book/integration/tests/graph/test_packet_consumers.py::test_packet_consumers_no_legacy_coupling",
        "book/integration/tests/runtime/test_runtime_promotion_contracts.py",
        "book/integration/tests/runtime/test_runtime_signatures_mapping.py",
    ]

    cmd = [sys.executable, "-m", "pytest", *tests]
    print(f"[ci] field2_hunt: running {' '.join(cmd)}", flush=True)
    subprocess.check_call(cmd, cwd=repo_root, env=env)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Run SANDBOX_LORE CI subsets.")
    parser.add_argument(
        "mode",
        nargs="?",
        default="all",
        choices=["all", "field2_hunt"],
        help="CI mode to run (default: all)",
    )
    args = parser.parse_args(argv)

    if args.mode == "field2_hunt":
        run_field2_hunt()
        return
    run_carton_validation()
    run_python_harness()
    run_swift_build()


if __name__ == "__main__":
    main()
