from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Tuple

from book.api import path_utils


ROOT = path_utils.find_repo_root(Path(__file__))


def resolve_bundle_dir(out_root: Path) -> Tuple[Path, str | None]:
    out_root = path_utils.ensure_absolute(out_root, repo_root=ROOT)
    latest = out_root / "LATEST"
    if latest.exists():
        run_id = latest.read_text().strip() or None
        if run_id:
            candidate = out_root / run_id
            if candidate.exists():
                return candidate, run_id
            raise AssertionError(f"LATEST points to missing run dir: {candidate}")
    return out_root, None


def load_bundle_json(out_root: Path, rel_path: str) -> Any:
    bundle_dir, _ = resolve_bundle_dir(out_root)
    path = bundle_dir / rel_path
    assert path.exists(), f"missing expected file: {path}"
    return json.loads(path.read_text())


def load_bundle_jsonl(out_root: Path, rel_path: str) -> list[dict]:
    bundle_dir, _ = resolve_bundle_dir(out_root)
    path = bundle_dir / rel_path
    assert path.exists(), f"missing expected file: {path}"
    rows: list[dict] = []
    for line in path.read_text().splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows
