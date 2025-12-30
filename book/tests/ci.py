#!/usr/bin/env python3
"""
Unified test/build driver for SANDBOX_LORE.

This is intentionally colocated with the test suite (`book/tests/`) so the
"how we run tests" harness lives next to the code it executes.

Supported entrypoint:
- `make -C book test` (invokes this module via `python -m book.tests.ci`)

This driver runs:
1) pytest (Python guardrails)
2) Swift graph build (static enforcement + generator compile)
"""

from __future__ import annotations

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


def run_swift_build() -> None:
    repo_root = _repo_root()
    book_root = _book_root(repo_root)

    env = os.environ.copy()
    env["SWIFT_BIN"] = env.get("SWIFT", "swift")

    module_cache = book_root / "graph" / ".module-cache"
    module_cache.mkdir(parents=True, exist_ok=True)
    env.setdefault("CLANG_MODULE_CACHE_PATH", str(module_cache))
    env.setdefault("SWIFTPM_MODULECACHE_OVERRIDE", str(module_cache))

    cmd = [sys.executable, "swift_build.py"]
    print(f"[ci] swift-build: running {' '.join(cmd)}", flush=True)
    subprocess.check_call(cmd, cwd=book_root / "graph", env=env)


def main() -> None:
    run_python_harness()
    run_swift_build()


if __name__ == "__main__":
    main()

