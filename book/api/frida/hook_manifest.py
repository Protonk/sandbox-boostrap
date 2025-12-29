"""Hook manifest helpers (headless, deterministic)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Optional

from book.api import path_utils
from book.api.frida import schema_validate


HOOK_MANIFEST_SCHEMA_NAME = "book.api.frida.hook_manifest"
HOOK_MANIFEST_SCHEMA_VERSION = 1


def sha256_bytes(blob: bytes) -> str:
    h = hashlib.sha256()
    h.update(blob)
    return h.hexdigest()


def sha256_canonical_json(obj: Any) -> str:
    blob = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256_bytes(blob)


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
            "sha256": None,
            "error": {"code": "manifest_invalid_json", "message": f"{type(exc).__name__}: {exc}"},
            "manifest": None,
            "violations": ["manifest must be valid JSON"],
        }
    if not isinstance(data, dict):
        return {
            "path": str(manifest_path),
            "sha256": None,
            "error": {"code": "manifest_invalid_shape", "message": "manifest must be a JSON object"},
            "manifest": None,
            "violations": ["manifest must be a JSON object"],
        }
    violations = schema_validate.validate_hook_manifest_v1(data)
    if violations:
        return {
            "path": str(manifest_path),
            "sha256": sha256_canonical_json(data),
            "error": {"code": "manifest_invalid_schema", "message": "schema violations"},
            "manifest": data,
            "violations": violations,
        }
    return {
        "path": str(manifest_path),
        "sha256": sha256_canonical_json(data),
        "error": None,
        "manifest": data,
        "violations": [],
    }


def load_manifest_snapshot(*, script_path: Path, repo_root: Path) -> Dict[str, Any]:
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
        return {
            "ok": snap.get("error") is None,
            "manifest": snap.get("manifest"),
            "manifest_path": path_utils.to_repo_relative(Path(str(snap.get("path"))), repo_root),
            "manifest_sha256": snap.get("sha256"),
            "manifest_error": snap.get("error"),
            "violations": snap.get("violations") or [],
        }

    return {
        "ok": False,
        "manifest": None,
        "manifest_path": None,
        "manifest_sha256": None,
        "manifest_error": {"code": "manifest_missing", "message": "no adjacent *.manifest.json found"},
        "violations": ["missing manifest file"],
    }
