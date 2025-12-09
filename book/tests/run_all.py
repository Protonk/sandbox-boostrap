#!/usr/bin/env python3
"""
Lightweight test harness for agents that cannot invoke pytest directly.

Mirrors the pytest collection in `book/tests` by importing each `test_*.py`
module, running module-level test callables, and executing any unittest
TestCase classes. Only a small fixture set is supported (`tmp_path`,
`monkeypatch`); extend sparingly if new tests require it.
"""

from __future__ import annotations

import importlib
import inspect
import os
import sys
import tempfile
import traceback
import unittest
from pathlib import Path
from typing import Callable, Iterable, List, Tuple

try:
    import pytest
except ImportError:  # pragma: no cover - pytest should already be available
    pytest = None

if pytest is None:
    sys.stderr.write("pytest is required to import tests (install it in your venv).\n")
    sys.exit(1)


ROOT = Path(__file__).resolve().parents[2]
TEST_DIR = Path(__file__).parent

# Align working directory + import path with pytest defaults
os.chdir(ROOT)
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


class Result:
    def __init__(self, name: str, ok: bool, error: str | None = None):
        self.name = name
        self.ok = ok
        self.error = error


def _discover_modules() -> List[str]:
    """
    Discover pytest-style modules:
    - `book/tests/test_*.py`
    - any `test_*.py` under `book/api/**` (e.g., runtime_harness)
    """
    modules: List[str] = []

    def to_module(path: Path) -> str:
        rel = path.relative_to(ROOT).with_suffix("")  # strip .py
        return ".".join(rel.parts)

    for path in sorted(TEST_DIR.glob("test_*.py")):
        modules.append(to_module(path))

    for path in sorted((ROOT / "book" / "api").rglob("test_*.py")):
        modules.append(to_module(path))

    return modules


def _run_callable(fn: Callable) -> Result:
    sig = inspect.signature(fn)
    kwargs = {}
    tmp_ctx = None
    mp = None

    for name in sig.parameters:
        if name == "tmp_path":
            tmp_ctx = tempfile.TemporaryDirectory()
            kwargs[name] = Path(tmp_ctx.name)
        elif name == "monkeypatch":
            if pytest is None:
                return Result(fn.__name__, False, "pytest is required for monkeypatch fixture")
            mp = pytest.MonkeyPatch()
            kwargs[name] = mp
        else:
            return Result(fn.__name__, False, f"unsupported fixture '{name}'")

    try:
        fn(**kwargs)
        return Result(fn.__name__, True)
    except Exception:
        tb = traceback.format_exc()
        return Result(fn.__name__, False, tb)
    finally:
        if mp:
            mp.undo()
        if tmp_ctx:
            tmp_ctx.cleanup()


def _run_unittest_classes(mod) -> Tuple[int, List[Result]]:
    suites = []
    for obj in vars(mod).values():
        if inspect.isclass(obj) and issubclass(obj, unittest.TestCase):
            suites.append(unittest.defaultTestLoader.loadTestsFromTestCase(obj))
    if not suites:
        return 0, []

    suite = unittest.TestSuite(suites)
    with open(os.devnull, "w") as sink:
        runner = unittest.TextTestRunner(stream=sink, verbosity=0)
        result = runner.run(suite)
    failures: List[Result] = []
    if not result.wasSuccessful():
        for case, err in result.failures + result.errors:
            failures.append(Result(case.id(), False, err))
    return result.testsRun, failures


def run_all() -> int:
    modules = _discover_modules()
    failures: List[Result] = []
    total_ran = 0

    for mod_name in modules:
        try:
            mod = importlib.import_module(mod_name)
        except Exception:
            tb = traceback.format_exc()
            failures.append(Result(mod_name, False, tb))
            continue

        ran, unit_failures = _run_unittest_classes(mod)
        total_ran += ran
        failures.extend(unit_failures)

        for name, obj in vars(mod).items():
            if inspect.isfunction(obj) and name.startswith("test_"):
                res = _run_callable(obj)
                total_ran += 1
                if not res.ok:
                    failures.append(res)

    if failures:
        print("Test failures:")
        for res in failures:
            print(f"- {res.name}: {res.error}")
        print(f"\n{len(failures)} failing test(s); ran {total_ran} total")
        return 1

    print(f"All tests passed ({total_ran} run)")
    return 0


if __name__ == "__main__":
    sys.exit(run_all())
