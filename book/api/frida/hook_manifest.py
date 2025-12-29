"""Hook manifest helpers (headless, deterministic)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Optional

from book.api import path_utils


HOOK_MANIFEST_SCHEMA_NAME = "book.api.frida.hook_manifest"
HOOK_MANIFEST_SCHEMA_VERSION = 1


def sha256_bytes(blob: bytes) -> str:
    h = hashlib.sha256()
    h.update(blob)
    return h.hexdigest()


def manifest_path_for_script(script_path: Path) -> Path:
    return script_path.with_suffix(".manifest.json")


def _try_load_manifest(manifest_path: Path) -> Optional[Dict[str, Any]]:
    if not manifest_path.exists():
        return None
    raw = manifest_path.read_bytes()
    try:
        data = json.loads(raw)
    except Exception as exc:
        return {
            "path": str(manifest_path),
            "sha256": sha256_bytes(raw),
            "error": f"invalid json: {type(exc).__name__}: {exc}",
            "manifest": None,
        }
    if not isinstance(data, dict):
        return {
            "path": str(manifest_path),
            "sha256": sha256_bytes(raw),
            "error": "manifest must be a JSON object",
            "manifest": None,
        }
    return {
        "path": str(manifest_path),
        "sha256": sha256_bytes(raw),
        "error": None,
        "manifest": data,
    }


def load_manifest_snapshot(*, script_path: Path, repo_root: Path) -> Optional[Dict[str, Any]]:
    """
    Load a hook manifest snapshot for a script path.

    Resolution order:
    1) `<script>.manifest.json` adjacent to the script path
    2) if the script is a symlink, `<resolved_script>.manifest.json` adjacent to the resolved path
    """
    candidates = [manifest_path_for_script(script_path)]
    try:
        resolved = script_path.resolve()
    except Exception:
        resolved = script_path
    if resolved != script_path:
        candidates.append(manifest_path_for_script(resolved))

    for cand in candidates:
        snap = _try_load_manifest(cand)
        if snap is None:
            continue
        # Make paths repo-relative in the serialized snapshot.
        out = dict(snap)
        out["path"] = path_utils.to_repo_relative(Path(out["path"]), repo_root)
        return out

    return None

