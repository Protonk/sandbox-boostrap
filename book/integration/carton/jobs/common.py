"""Shared helpers for CARTON jobs."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def _env(repo_root: Path) -> dict:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(repo_root)
    return env


def run_module(module: str, *, repo_root: Path) -> None:
    cmd = [sys.executable, "-m", module]
    subprocess.check_call(cmd, cwd=repo_root, env=_env(repo_root))


def run_script(path: Path, *, repo_root: Path) -> None:
    cmd = [sys.executable, str(path)]
    subprocess.check_call(cmd, cwd=repo_root, env=_env(repo_root))
