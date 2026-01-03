"""Fixer job wrappers."""

from __future__ import annotations

import importlib
from pathlib import Path
from typing import Callable


def make_runner(module_name: str, function_name: str = "run") -> Callable[[Path], None]:
    def _runner(_repo_root: Path) -> None:
        module = importlib.import_module(module_name)
        func = getattr(module, function_name)
        func()

    return _runner
