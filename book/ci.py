#!/usr/bin/env python3
"""
Unified test/build driver for SANDBOX_LORE.

Runs the pytest suite and the Swift graph build.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent            # book/
REPO_ROOT = ROOT.parent                           # repo root


def run_python_harness() -> None:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO_ROOT)
    cmd = [sys.executable, "-m", "pytest"]
    print(f"[ci] python-harness: running {' '.join(cmd)}", flush=True)
    subprocess.check_call(cmd, cwd=REPO_ROOT, env=env)


def run_swift_build() -> None:
    env = os.environ.copy()
    env["SWIFT_BIN"] = env.get("SWIFT", "swift")
    module_cache = ROOT / "graph" / ".module-cache"
    module_cache.mkdir(parents=True, exist_ok=True)
    env.setdefault("CLANG_MODULE_CACHE_PATH", str(module_cache))
    env.setdefault("SWIFTPM_MODULECACHE_OVERRIDE", str(module_cache))
    cmd = [sys.executable, "swift_build.py"]
    print(f"[ci] swift-build: running {' '.join(cmd)}", flush=True)
    subprocess.check_call(cmd, cwd=ROOT / "graph", env=env)


def main() -> None:
    run_python_harness()
    run_swift_build()


if __name__ == "__main__":
    main()
