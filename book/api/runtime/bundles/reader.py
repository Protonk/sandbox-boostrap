"""
Runtime artifact readers (service contract).

This module provides the "consumer" view of a runtime bundle.

Key invariants:
- Bundles are run-scoped directories under a bundle root: `out/<run_id>/...`.
- `out/LATEST` is a convenience pointer to the most recent committed run and is
  updated only after the run-scoped bundle is committed.
- `artifact_index.json` is the commit barrier: strict consumers should treat a
  bundle as loadable only if it has an index and is not `run_status.state ==
  in_progress`.

This module is intentionally strict by default (`load_bundle_index_strict`) and
also exposes a debug-friendly path (`open_bundle_unverified`) that never claims
the bundle is complete or promotable.

Treat a bundle like a signed packet of facts. We read it as-is and
verify digests before trusting anything that may inform downstream mappings.
"""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from book.api import path_utils


class BundleState(StrEnum):
    """
    State machine for `run_status.json`.

    - `in_progress`: the run is still writing artifacts; strict consumers must
      refuse to load it (no stable contract).
    - `complete`: the run recorded a final status (the commit barrier is still
      `artifact_index.json`).
    - `failed`: the run failed; an index may still exist for debugging.
    """

    IN_PROGRESS = "in_progress"
    COMPLETE = "complete"
    FAILED = "failed"


def _sha256_path(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            # Read in chunks to avoid loading large artifacts into memory.
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _latest_run_id(bundle_root: Path) -> Optional[str]:
    latest = bundle_root / "LATEST"
    if not latest.exists():
        return None
    value = latest.read_text(encoding="utf-8", errors="ignore").strip()
    return value or None


def resolve_bundle_dir(bundle_dir: Path, *, repo_root: Path) -> Tuple[Path, Optional[str]]:
    """
    Resolve a bundle root to a run-scoped directory using `LATEST` when present.

    Returns `(resolved_dir, run_id)` where run_id is `None` when the input is
    already run-scoped or when `LATEST` does not exist.
    """

    bundle_dir = path_utils.ensure_absolute(bundle_dir, repo_root)
    run_id = _latest_run_id(bundle_dir)
    if run_id:
        candidate = bundle_dir / run_id
        if candidate.exists():
            return candidate, run_id
        raise FileNotFoundError(f"LATEST points to missing run dir: {run_id} ({bundle_dir})")
    return bundle_dir, None


def load_bundle_index_strict(bundle_dir: Path, *, repo_root: Path) -> Dict[str, Any]:
    """
    Strictly load and verify a committed bundle.

    Guarantees on success:
    - The bundle is not `in_progress`.
    - `artifact_index.json` exists and every indexed artifact exists and matches
      its recorded digest.
    """

    bundle_dir, _ = resolve_bundle_dir(bundle_dir, repo_root=repo_root)
    status_path = bundle_dir / "run_status.json"
    if status_path.exists():
        status_doc = json.loads(status_path.read_text(encoding="utf-8", errors="ignore"))
        state = status_doc.get("state")
        if state == BundleState.IN_PROGRESS:
            raise RuntimeError(f"bundle is in progress: {path_utils.to_repo_relative(bundle_dir, repo_root=repo_root)}")
    index_path = bundle_dir / "artifact_index.json"
    if not index_path.exists():
        raise FileNotFoundError(f"missing artifact_index.json in {bundle_dir}")
    index = json.loads(index_path.read_text(encoding="utf-8", errors="ignore"))
    artifacts = index.get("artifacts") or []
    for entry in artifacts:
        path = path_utils.ensure_absolute(Path(entry["path"]), repo_root)
        if not path.exists():
            raise FileNotFoundError(f"missing artifact: {entry['path']}")
        expected = entry.get("sha256")
        if expected and _sha256_path(path) != expected:
            raise ValueError(f"digest mismatch for {entry['path']}")
    return index


def open_bundle_unverified(bundle_dir: Path, *, repo_root: Path) -> Dict[str, Any]:
    """
    Load what is present without enforcing completeness or digest integrity.

    This is intended for debugging and failure reports. Callers must not treat
    this as evidence that the bundle is committed or promotable.
    """

    bundle_dir, _ = resolve_bundle_dir(bundle_dir, repo_root=repo_root)
    bundle_dir = path_utils.ensure_absolute(bundle_dir, repo_root)
    index_path = bundle_dir / "artifact_index.json"
    status_path = bundle_dir / "run_status.json"
    payload: Dict[str, Any] = {
        "bundle_dir": str(path_utils.to_repo_relative(bundle_dir, repo_root=repo_root)),
        "integrity": "unverified",
        "artifact_index_present": index_path.exists(),
        "run_status_present": status_path.exists(),
        "missing": [],
        "digest_mismatches": [],
    }
    if status_path.exists():
        payload["run_status"] = json.loads(status_path.read_text(encoding="utf-8", errors="ignore"))
    if not index_path.exists():
        return payload
    index = json.loads(index_path.read_text(encoding="utf-8", errors="ignore"))
    payload["artifact_index"] = index
    for entry in index.get("artifacts") or []:
        rel = entry.get("path")
        if not rel:
            continue
        path = path_utils.ensure_absolute(Path(rel), repo_root)
        if not path.exists():
            payload["missing"].append(rel)
            continue
        expected = entry.get("sha256")
        if expected and _sha256_path(path) != expected:
            payload["digest_mismatches"].append(rel)
    return payload
