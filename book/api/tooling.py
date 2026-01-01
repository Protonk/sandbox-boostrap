"""Shared tool provenance helpers."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Dict, Optional

from book.api import path_utils


_SHA256_CACHE: Dict[str, str] = {}


def sha256_path(path: Path) -> str:
    key = str(path)
    cached = _SHA256_CACHE.get(key)
    if cached:
        return cached
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    _SHA256_CACHE[key] = digest
    return digest


def runner_info(
    entrypoint_path: Path,
    *,
    repo_root: Optional[Path] = None,
    entrypoint: Optional[str] = None,
) -> Dict[str, object]:
    repo_root = repo_root or path_utils.find_repo_root(Path(__file__))
    rel_path = path_utils.to_repo_relative(entrypoint_path, repo_root=repo_root)
    info: Dict[str, object] = {
        "entrypoint": entrypoint or entrypoint_path.name,
        "entrypoint_path": rel_path,
    }
    if entrypoint_path.exists():
        digest = sha256_path(entrypoint_path)
        info["entrypoint_sha256"] = digest
        info["tool_build_id"] = digest
    else:
        info["entrypoint_sha256"] = None
        info["tool_build_id"] = None
        info["entrypoint_missing"] = True
    return info
