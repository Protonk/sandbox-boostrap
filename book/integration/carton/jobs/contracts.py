"""Contract + manifest job wrappers."""

from __future__ import annotations

from pathlib import Path

from book.integration.carton import bundle
from book.integration.carton import paths


def build_manifest(repo_root: Path) -> None:
    spec_path = paths.ensure_absolute(paths.CARTON_SPEC, repo_root_path=repo_root)
    manifest_path = paths.ensure_absolute(paths.MANIFEST_PATH, repo_root_path=repo_root)
    bundle.build_manifest(
        spec_path=spec_path,
        out_path=manifest_path,
        repo_root=repo_root,
        refresh_contracts=True,
    )
