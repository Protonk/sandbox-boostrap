#!/usr/bin/env python3
"""
Unified CI/validation driver for SANDBOX_LORE.

Runs the Python test harness and the Swift graph build once, with
coarse-grained stamps to avoid rerunning expensive steps when inputs
haven’t changed.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from hashlib import sha256
from pathlib import Path
from typing import Iterable, List

ROOT = Path(__file__).resolve().parent            # book/
REPO_ROOT = ROOT.parent                           # repo root
STAMP_DIR = ROOT / "out" / "ci-stamps"
STAMP_DIR.mkdir(parents=True, exist_ok=True)


def _fingerprint(paths: Iterable[Path]) -> str:
    """
    Build a stable fingerprint across files in the provided paths using
    size + mtime for speed (not content hash). Directory inputs are
    expanded recursively.
    """
    entries: List[str] = []
    for path in sorted(set(paths)):
        if not path.exists():
            entries.append(f"missing:{path}")
            continue
        if path.is_dir():
            for child in sorted(path.rglob("*")):
                if child.is_file():
                    st = child.stat()
                    entries.append(f"{child.relative_to(REPO_ROOT)}:{st.st_size}:{st.st_mtime_ns}")
        else:
            st = path.stat()
            entries.append(f"{path.relative_to(REPO_ROOT)}:{st.st_size}:{st.st_mtime_ns}")
    return sha256("\n".join(entries).encode("utf-8")).hexdigest()


def _run_step(name: str, inputs: Iterable[Path], cmd: List[str], cwd: Path | None = None, env: dict | None = None) -> None:
    stamp = STAMP_DIR / f"{name}.json"
    fingerprint = _fingerprint(inputs)

    if stamp.exists():
        prev = json.loads(stamp.read_text())
        if prev.get("fingerprint") == fingerprint:
            print(f"[ci] {name}: up-to-date", flush=True)
            return

    print(f"[ci] {name}: running {' '.join(cmd)}", flush=True)
    subprocess.check_call(cmd, cwd=cwd, env=env)
    stamp.write_text(json.dumps({"fingerprint": fingerprint}, indent=2))


def run_python_harness() -> None:
    inputs = [
        ROOT / "tests",
        ROOT / "api",
        ROOT / "graph" / "concepts" / "validation",
        ROOT / "examples",
        ROOT / "experiments",
    ]
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO_ROOT)
    _run_step(
        "python-harness",
        inputs,
        [sys.executable, "-m", "book.tests.run_all"],
        cwd=ROOT,
        env=env,
    )


def run_swift_build() -> None:
    inputs = [
        ROOT / "graph" / "Package.swift",
        ROOT / "graph" / "swift",
    ]
    env = os.environ.copy()
    env["SWIFT_BIN"] = env.get("SWIFT", "swift")
    _run_step(
        "swift-build",
        inputs,
        [sys.executable, "swift_build.py"],
        cwd=ROOT / "graph",
        env=env,
    )


def main() -> None:
    run_python_harness()
    run_swift_build()


if __name__ == "__main__":
    main()
