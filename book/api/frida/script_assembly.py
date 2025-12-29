"""Deterministic Frida script assembly (shared helper + hook source)."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Dict, Tuple

from book.api import path_utils


def _sha256_bytes(blob: bytes) -> str:
    h = hashlib.sha256()
    h.update(blob)
    return h.hexdigest()


def helper_path(repo_root: Path) -> Path:
    return repo_root / "book/api/frida/hooks/_shared/trace_helper.js"


def assemble_script_source(*, script_path: Path, repo_root: Path) -> Tuple[bytes, Dict[str, Any]]:
    """
    Assemble the script source deterministically.

    Returns (assembled_bytes, assembly_meta).
    """
    helper = helper_path(repo_root)
    helper_bytes = helper.read_bytes()
    hook_bytes = script_path.read_bytes()

    sep = b"\n\n"
    assembled = helper_bytes
    if not assembled.endswith(b"\n"):
        assembled += b"\n"
    assembled += sep
    assembled += hook_bytes
    if not assembled.endswith(b"\n"):
        assembled += b"\n"

    return assembled, {
        "assembly_version": 1,
        "helper": {
            "path": path_utils.to_repo_relative(helper, repo_root),
            "sha256": _sha256_bytes(helper_bytes),
        },
        "assembled_sha256": _sha256_bytes(assembled),
    }

