"""
Pytest support for SANDBOX_LORE.

This file is intentionally a *single* module (not a package) and is loaded as a
pytest plugin via `pytest.ini` (`-p book.integration.support`).

What belongs here:
- Tiny, boring helpers that many tests want (especially subprocess capture).
- The minimal pytest hooks/fixtures needed to make failures debuggable.
- "Last run only" artifact emission under `book/integration/out/`.

What does *not* belong here:
- Seatbelt semantics or host-policy claims (those belong in tests + evidence).
- Large domain logic (that belongs in `book/api/*` or `book/tools/*`).
- Run comparison / golden-run machinery (we intentionally removed it).
"""

from __future__ import annotations

import json
import platform
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping, Sequence

import pytest

# `make -C book test` runs pytest from inside `book/`, which means the *repo
# root* is not necessarily on `sys.path`. We add it explicitly so that imports
# like `from book.api import ...` resolve to the repo's `book/` package.
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api import path_utils, world as world_api


def _sanitize_nodeid(nodeid: str) -> str:
    # Pytest nodeids contain characters that are meaningful to pytest but not
    # filesystem-friendly (slashes, brackets, spaces). We map them to a stable
    # directory name so each test can have its own artifact folder.
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", nodeid)


def _resolve_artifacts_root(repo_root: Path) -> Path:
    # All tests emit artifacts into a single, non-versioned directory.
    # "Last run wins" is a design choice: no timestamps, no UUIDs, no diffing.
    return repo_root / "book" / "integration" / "out"


def _reset_artifacts_root(artifacts_root: Path) -> None:
    # Start every run from a clean slate so that:
    # - failures don't get confused with stale output
    # - users can reliably share `book/integration/out/` as "the last run"
    if artifacts_root.exists():
        shutil.rmtree(artifacts_root)
    artifacts_root.mkdir(parents=True, exist_ok=True)


def pytest_configure(config: pytest.Config) -> None:
    # Called early in pytest startup for every process.
    #
    # Note: If users run with xdist (`-n ...`), this hook runs in the controller
    # *and* in each worker. We therefore only wipe `book/integration/out/` in the
    # controller process to avoid races. The rest of this module is "best
    # effort" under xdist; the supported runner is the default (no xdist).
    repo_root = path_utils.find_repo_root(Path(__file__))
    artifacts_root = _resolve_artifacts_root(repo_root)
    if getattr(config, "workerinput", None) is None:
        _reset_artifacts_root(artifacts_root)
    else:
        artifacts_root.mkdir(parents=True, exist_ok=True)

    # Pytest doesn't give us a typed "plugin state bag", so we attach a few
    # private attributes to the `Config` object. The leading underscore reduces
    # the chance of collisions with other plugins.
    config._sandboxlore_repo_root = repo_root
    config._sandboxlore_artifacts_root = artifacts_root
    config._sandboxlore_counts = {"passed": 0, "failed": 0, "skipped": 0, "xfailed": 0, "xpassed": 0}

    # A small machine-readable record for "what did I just run?".
    # This is intended for humans *and* for any future tooling that wants to
    # locate artifacts without scraping stdout.
    run_meta = {
        "schema_version": 1,
        "started_at": datetime.now(timezone.utc).isoformat(),
        # Persist as repo-relative so the bundle is portable across checkouts.
        "artifacts_root": path_utils.to_repo_relative(artifacts_root, repo_root=repo_root),
        "python": {
            "executable": sys.executable,
            "version": sys.version,
        },
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
    }

    try:
        # Best-effort: tests should still run even if the world registry is
        # broken, but we want the failure to be visible in the artifacts.
        world_doc, resolution = world_api.load_world(repo_root=repo_root)
        world_id = world_api.require_world_id(world_doc, world_path=resolution.entry.world_path)
        run_meta["world"] = {
            "world_id": world_id,
            "world_path": world_api.world_path_for_metadata(resolution, repo_root=repo_root),
        }
    except Exception as exc:  # pragma: no cover - best-effort metadata
        # Important: we record the error rather than swallowing it silently.
        # If the world registry is broken, that's a high-signal repo problem.
        run_meta["world"] = {"error": str(exc)}

    # `run.json` is written at configure time so it exists even if collection
    # fails or the session aborts early.
    (artifacts_root / "run.json").write_text(json.dumps(run_meta, indent=2))


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    # Session-level summary written at the very end of the run.
    config = session.config
    artifacts_root = config._sandboxlore_artifacts_root
    counts = dict(config._sandboxlore_counts)
    summary = {
        "schema_version": 1,
        "exit_status": exitstatus,
        "counts": counts,
        "collected": session.testscollected,
        "finished_at": datetime.now(timezone.utc).isoformat(),
    }
    (artifacts_root / "summary.json").write_text(json.dumps(summary, indent=2))


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo):
    # Hook wrapper so we can let pytest compute the report, then post-process it
    # into stable artifacts and counters.
    outcome = yield
    report = outcome.get_result()
    # We only record the "call" phase. Setup/teardown failures already show up
    # in pytest's output, but they are usually less useful for the per-test
    # artifact bundle (and can be noisy).
    if report.when != "call":
        return

    # Maintain a minimal count summary for `summary.json`.
    counts = item.config._sandboxlore_counts
    if getattr(report, "wasxfail", None):
        if report.outcome == "passed":
            counts["xpassed"] += 1
        else:
            counts["xfailed"] += 1
    elif report.outcome in counts:
        counts[report.outcome] += 1

    # Each test gets its own artifact directory keyed by nodeid.
    artifacts_root = item.config._sandboxlore_artifacts_root
    node_dir = artifacts_root / _sanitize_nodeid(item.nodeid)
    node_dir.mkdir(parents=True, exist_ok=True)

    # Small structured record for quick scanning / tooling.
    record = {
        "nodeid": item.nodeid,
        "outcome": report.outcome,
        "duration_s": round(report.duration, 6),
    }
    if report.failed:
        # Include the long representation in both JSON and a plain text file.
        # The text file is convenient to open directly in an editor.
        record["longrepr"] = str(report.longrepr)
        (node_dir / "failure.txt").write_text(str(report.longrepr))
    (node_dir / "report.json").write_text(json.dumps(record, indent=2))


@pytest.fixture(scope="session")
def repo_root(request: pytest.FixtureRequest) -> Path:
    # Session fixture for "where is the repo checkout?".
    # This is the root that contains `book/`, `pytest.ini`, etc.
    return request.config._sandboxlore_repo_root


@pytest.fixture(scope="session")
def book_root(repo_root: Path) -> Path:
    # Convenience: many tests want to refer to the operational root `book/`.
    return repo_root / "book"


@pytest.fixture
def artifact_dir(request: pytest.FixtureRequest) -> Path:
    # Per-test artifact directory, created lazily when the fixture is requested.
    # Tests can write additional debug files here without inventing their own
    # output naming scheme.
    root = request.config._sandboxlore_artifacts_root
    node_dir = root / _sanitize_nodeid(request.node.nodeid)
    node_dir.mkdir(parents=True, exist_ok=True)
    return node_dir


def _repo_root() -> Path:
    # We prefer `path_utils.find_repo_root()` over `REPO_ROOT` for conversions
    # that may happen in subprocess helpers, because it encodes the repo's
    # definition of "root" and keeps the code consistent.
    return path_utils.find_repo_root(Path(__file__))


def _as_str_seq(cmd: Sequence[object]) -> list[str]:
    # `subprocess.run()` expects strings; tests often pass Paths or other
    # objects. Converting early keeps command emission consistent.
    return [str(part) for part in cmd]


def _run_cmd(
    cmd: Sequence[object],
    *,
    cwd: str | Path | None = None,
    env: Mapping[str, str] | None = None,
    timeout: float | None = None,
    check: bool = False,
    artifact_dir: str | Path | None = None,
    label: str = "command",
) -> subprocess.CompletedProcess:
    # Core subprocess runner for tests.
    #
    # This is intentionally tiny: run a command, capture stdout/stderr, and
    # optionally emit a structured artifact bundle under the current test's
    # artifact directory.
    #
    # The intent is that failures are diagnosable without re-running the test:
    # `command.json` points to `stdout.txt` / `stderr.txt`, and includes a
    # repo-relative argv and cwd (no `/Users/...` leaks in committed output).
    argv = _as_str_seq(cmd)
    start = time.monotonic()
    result = subprocess.run(
        argv,
        # Always capture output so tests can attach it to `book/integration/out/` and
        # AssertionErrors can include stderr in the message.
        capture_output=True,
        text=True,
        cwd=str(cwd) if cwd is not None else None,
        # `None` means "inherit the current environment".
        env=env,
        timeout=timeout,
    )
    duration = time.monotonic() - start

    if artifact_dir is not None:
        repo_root = _repo_root()
        art = Path(artifact_dir)
        art.mkdir(parents=True, exist_ok=True)
        # These filenames are stable so a reader can "just open the folder".
        (art / "stdout.txt").write_text(result.stdout or "")
        (art / "stderr.txt").write_text(result.stderr or "")
        record = {
            "label": label,
            # Relativize the command so artifacts are portable across machines.
            "argv": path_utils.relativize_command(argv, repo_root=repo_root),
            # Keep cwd portable for the same reason.
            "cwd": path_utils.to_repo_relative(cwd, repo_root=repo_root) if cwd is not None else None,
            "returncode": result.returncode,
            "duration_s": round(duration, 6),
            "stdout_path": "stdout.txt",
            "stderr_path": "stderr.txt",
        }
        (art / "command.json").write_text(json.dumps(record, indent=2))

    if check and result.returncode != 0:
        # When `check=True`, we raise an AssertionError instead of returning the
        # failing process result. This makes tests read cleanly:
        # `run_cmd([...], check=True, label="...")`.
        msg = f"{label} failed with code {result.returncode}"
        if artifact_dir is not None:
            rel_art = path_utils.to_repo_relative(Path(artifact_dir), repo_root=_repo_root())
            msg += f"; see {rel_art}/command.json"
        if result.stderr:
            # Include stderr inline because it's the fastest clue during triage.
            msg += f"\nstderr:\n{result.stderr.strip()}"
        raise AssertionError(msg)

    return result


@pytest.fixture
def run_cmd(artifact_dir: Path):
    # Public fixture used by tests.
    #
    # It pre-binds the current test's `artifact_dir` so every command the test
    # runs automatically leaves behind a bundle in `book/integration/out/<nodeid>/`.
    def _run(cmd, *, cwd=None, env=None, timeout=None, check=False, label="command"):
        return _run_cmd(
            cmd,
            cwd=cwd,
            env=env,
            timeout=timeout,
            check=check,
            artifact_dir=artifact_dir,
            label=label,
        )

    return _run
