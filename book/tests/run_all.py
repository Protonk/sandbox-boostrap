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
import types
import unittest
from pathlib import Path
from typing import Callable, Iterable, List, Tuple

# Provide a minimal pytest stub when the package is unavailable.
try:
    import pytest  # type: ignore
except ImportError:  # pragma: no cover - fallback stub
    class _RaisesContext:
        def __init__(self, expected_exc):
            self.expected_exc = expected_exc

        def __enter__(self):
            return None

        def __exit__(self, exc_type, exc, tb):
            if exc is None:
                raise AssertionError(f"Did not raise {self.expected_exc}")
            if not issubclass(exc_type, self.expected_exc):
                return False
            return True

    class _MonkeyPatch:
        def __init__(self):
            self._actions = []

        def setattr(self, obj, name, value):
            had_attr = hasattr(obj, name)
            old = getattr(obj, name, None)
            self._actions.append(("setattr", obj, name, old, had_attr))
            setattr(obj, name, value)

        def setenv(self, key, value):
            had = key in os.environ
            old = os.environ.get(key)
            self._actions.append(("setenv", None, key, old, had))
            os.environ[key] = value

        def delenv(self, key, raising=True):
            had = key in os.environ
            old = os.environ.get(key)
            self._actions.append(("setenv", None, key, old, had))
            try:
                del os.environ[key]
            except KeyError:
                if raising:
                    raise

        def undo(self):
            # Restore in reverse order
            for action in reversed(self._actions):
                kind, obj, name_or_key, old, had = action
                if kind == "setattr":
                    if had:
                        setattr(obj, name_or_key, old)
                    else:
                        delattr(obj, name_or_key)
                elif kind == "setenv":
                    if had:
                        os.environ[name_or_key] = old if old is not None else ""
                    else:
                        os.environ.pop(name_or_key, None)
            self._actions = []

    class _Mark:
        def __getattr__(self, _name):
            def decorator(fn):
                return fn

            return decorator

    stub = types.SimpleNamespace(
        MonkeyPatch=_MonkeyPatch,
        raises=lambda exc: _RaisesContext(exc),
        mark=_Mark(),
    )
    sys.modules["pytest"] = stub
    pytest = stub  # type: ignore


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
    - any `test_*.py` under `book/api/**` (e.g., runtime)
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

        for name, obj in list(vars(mod).items()):
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
