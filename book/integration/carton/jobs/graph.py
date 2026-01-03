"""Swift graph tool runners for CARTON."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def _graph_root(repo_root: Path) -> Path:
    return repo_root / "book" / "integration" / "carton" / "graph"


def _swift_env(graph_root: Path) -> dict:
    env = os.environ.copy()
    env["SWIFT_BIN"] = env.get("SWIFT", "swift")
    module_cache = graph_root / ".module-cache"
    module_cache.mkdir(parents=True, exist_ok=True)
    env.setdefault("CLANG_MODULE_CACHE_PATH", str(module_cache))
    env.setdefault("SWIFTPM_MODULECACHE_OVERRIDE", str(module_cache))
    return env


def run_swift_build(repo_root: Path) -> None:
    graph_root = _graph_root(repo_root)
    env = _swift_env(graph_root)
    cmd = [sys.executable, "swift_build.py"]
    subprocess.check_call(cmd, cwd=graph_root, env=env)


def run_swift_run(repo_root: Path) -> None:
    graph_root = _graph_root(repo_root)
    env = _swift_env(graph_root)
    swift_bin = env.get("SWIFT_BIN", "swift")
    cmd = [swift_bin, "run", "--disable-sandbox"]
    subprocess.check_call(cmd, cwd=graph_root, env=env)
