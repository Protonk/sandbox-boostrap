from __future__ import annotations

import json
import os
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

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api import path_utils, world as world_api


def _sanitize_nodeid(nodeid: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", nodeid)


def _resolve_artifacts_root(repo_root: Path) -> Path:
    return repo_root / "book" / "tests" / "out"


def _reset_artifacts_root(artifacts_root: Path) -> None:
    if artifacts_root.exists():
        shutil.rmtree(artifacts_root)
    artifacts_root.mkdir(parents=True, exist_ok=True)


def pytest_configure(config: pytest.Config) -> None:
    repo_root = path_utils.find_repo_root(Path(__file__))
    artifacts_root = _resolve_artifacts_root(repo_root)
    if getattr(config, "workerinput", None) is None:
        _reset_artifacts_root(artifacts_root)
    else:
        artifacts_root.mkdir(parents=True, exist_ok=True)
    config._sandboxlore_repo_root = repo_root
    config._sandboxlore_artifacts_root = artifacts_root
    config._sandboxlore_counts = {"passed": 0, "failed": 0, "skipped": 0, "xfailed": 0, "xpassed": 0}

    run_meta = {
        "schema_version": 1,
        "started_at": datetime.now(timezone.utc).isoformat(),
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
        world_doc, resolution = world_api.load_world(repo_root=repo_root)
        world_id = world_api.require_world_id(world_doc, world_path=resolution.entry.world_path)
        run_meta["world"] = {
            "world_id": world_id,
            "world_path": world_api.world_path_for_metadata(resolution, repo_root=repo_root),
        }
    except Exception as exc:  # pragma: no cover - best-effort metadata
        run_meta["world"] = {"error": str(exc)}

    (artifacts_root / "run.json").write_text(json.dumps(run_meta, indent=2))


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
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
    outcome = yield
    report = outcome.get_result()
    if report.when != "call":
        return
    counts = item.config._sandboxlore_counts
    if getattr(report, "wasxfail", None):
        if report.outcome == "passed":
            counts["xpassed"] += 1
        else:
            counts["xfailed"] += 1
    elif report.outcome in counts:
        counts[report.outcome] += 1
    artifacts_root = item.config._sandboxlore_artifacts_root
    node_dir = artifacts_root / _sanitize_nodeid(item.nodeid)
    node_dir.mkdir(parents=True, exist_ok=True)

    record = {
        "nodeid": item.nodeid,
        "outcome": report.outcome,
        "duration_s": round(report.duration, 6),
    }
    if report.failed:
        record["longrepr"] = str(report.longrepr)
        (node_dir / "failure.txt").write_text(str(report.longrepr))
    (node_dir / "report.json").write_text(json.dumps(record, indent=2))


@pytest.fixture(scope="session")
def repo_root(request: pytest.FixtureRequest) -> Path:
    return request.config._sandboxlore_repo_root


@pytest.fixture(scope="session")
def book_root(repo_root: Path) -> Path:
    return repo_root / "book"


@pytest.fixture
def artifact_dir(request: pytest.FixtureRequest) -> Path:
    root = request.config._sandboxlore_artifacts_root
    node_dir = root / _sanitize_nodeid(request.node.nodeid)
    node_dir.mkdir(parents=True, exist_ok=True)
    return node_dir


def _repo_root() -> Path:
    return path_utils.find_repo_root(Path(__file__))


def _as_str_seq(cmd: Sequence[object]) -> list[str]:
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
    """Run a subprocess and optionally emit a structured artifact bundle."""
    argv = _as_str_seq(cmd)
    start = time.monotonic()
    result = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        cwd=str(cwd) if cwd is not None else None,
        env=env,
        timeout=timeout,
    )
    duration = time.monotonic() - start

    if artifact_dir is not None:
        repo_root = _repo_root()
        art = Path(artifact_dir)
        art.mkdir(parents=True, exist_ok=True)
        (art / "stdout.txt").write_text(result.stdout or "")
        (art / "stderr.txt").write_text(result.stderr or "")
        record = {
            "label": label,
            "argv": path_utils.relativize_command(argv, repo_root=repo_root),
            "cwd": path_utils.to_repo_relative(cwd, repo_root=repo_root) if cwd is not None else None,
            "returncode": result.returncode,
            "duration_s": round(duration, 6),
            "stdout_path": "stdout.txt",
            "stderr_path": "stderr.txt",
        }
        (art / "command.json").write_text(json.dumps(record, indent=2))

    if check and result.returncode != 0:
        msg = f"{label} failed with code {result.returncode}"
        if artifact_dir is not None:
            rel_art = path_utils.to_repo_relative(Path(artifact_dir), repo_root=_repo_root())
            msg += f"; see {rel_art}/command.json"
        if result.stderr:
            msg += f"\nstderr:\n{result.stderr.strip()}"
        raise AssertionError(msg)

    return result


@pytest.fixture
def run_cmd(artifact_dir: Path):
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
