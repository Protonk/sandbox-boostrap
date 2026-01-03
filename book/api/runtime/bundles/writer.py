"""
Runtime artifact writers (service contract).

This module owns the mechanics of writing runtime bundle artifacts in a
way that supports the bundle invariants:

- Writes are atomic at the file level (write to a temporary path, then replace).
- `artifact_index.json` is the commit barrier for a run-scoped bundle directory:
  consumers treat a bundle as "committed" only once the index exists.
- The index records stable metadata (repo-relative path, file size, digest, and
  per-artifact schema_version when available).

This module assumes the caller has already chosen an output directory and (for
concurrent writers) acquired any necessary bundle-root lock. This module does
not run probes, interpret outcomes, or decide promotability.

Atomic writes + explicit commit markers let other tools read bundles
without races. This is a small reliability trick that pays off when runs are
expensive to reproduce.
"""

from __future__ import annotations

import hashlib
import json
import os
from enum import StrEnum
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from book.api import path_utils


class ArtifactIndexStatus(StrEnum):
    """
    Status for `artifact_index.json`.

    - `ok`: all expected artifacts exist and were indexed.
    - `partial`: some expected artifacts are missing (typical for lane-disabled
      runs or mid-run failures where the index is still written for debugging).
    - `failed`: the run failed; this is a stronger signal than `partial`.
    """

    OK = "ok"
    PARTIAL = "partial"
    FAILED = "failed"


def write_json_atomic(path: Path, payload: Dict[str, Any]) -> None:
    """Write a JSON payload atomically to the target path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    # Keep temp file in the same directory so rename stays atomic.
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def write_text_atomic(path: Path, text: str) -> None:
    """Write plain text atomically to the target path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    # Use a sibling temp file so os.replace remains an atomic swap.
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def sha256_path(path: Path) -> str:
    """Return the SHA-256 hex digest for the file at path."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def extract_schema_version(path: Path) -> Optional[str]:
    """Extract a schema_version from a JSON/JSONL artifact when present."""
    if path.suffix == ".jsonl":
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except Exception:
                return None
            return row.get("schema_version") if isinstance(row, dict) else None
        return None
    if path.suffix == ".json":
        try:
            doc = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            return None
        if isinstance(doc, dict):
            return doc.get("schema_version")
    return None


def write_artifact_index(
    out_dir: Path,
    *,
    run_id: str,
    world_id: str,
    schema_version: str,
    expected_artifacts: Iterable[str],
    repo_root: Path,
    status_override: Optional[str] = None,
) -> Path:
    """Write the bundle commit index and return its path."""
    artifacts = []
    missing = []
    for name in expected_artifacts:
        path = out_dir / name
        if not path.exists():
            missing.append(path_utils.to_repo_relative(path, repo_root=repo_root))
            continue
        artifacts.append(
            {
                "path": path_utils.to_repo_relative(path, repo_root=repo_root),
                "file_size": path.stat().st_size,
                "sha256": sha256_path(path),
                "schema_version": extract_schema_version(path),
            }
        )
    status = status_override or (ArtifactIndexStatus.OK.value if not missing else ArtifactIndexStatus.PARTIAL.value)
    index = {
        "schema_version": schema_version,
        "run_id": run_id,
        "world_id": world_id,
        "artifacts": artifacts,
        "missing": missing,
        "status": status,
    }
    path = out_dir / "artifact_index.json"
    write_json_atomic(path, index)
    return path
