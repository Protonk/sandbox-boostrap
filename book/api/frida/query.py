"""DuckDB-first query/index surface for Frida trace runs (headless)."""

from __future__ import annotations

import json
import subprocess
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional

from book.api import path_utils


class DuckDBError(Exception):
    pass


def _duckdb_cmd() -> str:
    path = shutil.which("duckdb")
    if not path:
        raise DuckDBError("duckdb CLI not found in PATH (required for frida query/index)")
    return path


def _run_duckdb_json(*, db_path: Optional[Path], sql: str) -> Any:
    cmd: List[str] = [_duckdb_cmd(), "-no-stdin", "-json", "-c", sql]
    if db_path is not None:
        cmd.insert(1, str(db_path))
    try:
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as exc:
        raise DuckDBError(f"duckdb failed (rc={exc.returncode}): {exc.output}") from exc
    try:
        return json.loads(out) if out.strip() else []
    except Exception as exc:
        raise DuckDBError(f"duckdb returned non-JSON output: {type(exc).__name__}: {exc}") from exc


def index_path_for_run_dir(run_dir: Path) -> Path:
    return run_dir / "index.duckdb"


def build_index(*, run_dir: Path, index_path: Optional[Path] = None) -> Dict[str, Any]:
    repo_root = path_utils.find_repo_root()
    run_dir_abs = path_utils.ensure_absolute(run_dir, repo_root)
    events_path = run_dir_abs / "events.jsonl"

    idx_path = path_utils.ensure_absolute(index_path or index_path_for_run_dir(run_dir_abs), repo_root)
    idx_path.parent.mkdir(parents=True, exist_ok=True)

    sql = (
        "PRAGMA threads=1;"
        "DROP TABLE IF EXISTS events;"
        f"CREATE TABLE events AS SELECT * FROM read_json_auto('{events_path.as_posix()}');"
    )
    _run_duckdb_json(db_path=idx_path, sql=sql)
    row_count = _run_duckdb_json(db_path=idx_path, sql="PRAGMA threads=1; SELECT COUNT(*) AS n FROM events;")
    n = row_count[0].get("n") if isinstance(row_count, list) and row_count else None
    return {
        "ok": True,
        "run_dir": path_utils.to_repo_relative(run_dir_abs, repo_root),
        "events_path": path_utils.to_repo_relative(events_path, repo_root),
        "index_path": path_utils.to_repo_relative(idx_path, repo_root),
        "events_rows": n,
    }


def query_run_dir(
    *,
    run_dir: Path,
    sql: str,
    use_index: bool,
    index_path: Optional[Path] = None,
) -> Dict[str, Any]:
    repo_root = path_utils.find_repo_root()
    run_dir_abs = path_utils.ensure_absolute(run_dir, repo_root)
    events_path = run_dir_abs / "events.jsonl"

    if use_index:
        idx_path = path_utils.ensure_absolute(index_path or index_path_for_run_dir(run_dir_abs), repo_root)
        result = _run_duckdb_json(db_path=idx_path, sql=f"PRAGMA threads=1; {sql}")
        return {
            "ok": True,
            "mode": "index",
            "run_dir": path_utils.to_repo_relative(run_dir_abs, repo_root),
            "index_path": path_utils.to_repo_relative(idx_path, repo_root),
            "result": result,
        }

    prefix = f"PRAGMA threads=1; CREATE OR REPLACE VIEW events AS SELECT * FROM read_json_auto('{events_path.as_posix()}');"
    result = _run_duckdb_json(db_path=None, sql=f"{prefix} {sql}")
    return {
        "ok": True,
        "mode": "direct",
        "run_dir": path_utils.to_repo_relative(run_dir_abs, repo_root),
        "events_path": path_utils.to_repo_relative(events_path, repo_root),
        "result": result,
    }
