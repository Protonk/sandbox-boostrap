"""Path helpers for CARTON bundle layout."""

from __future__ import annotations

from pathlib import Path

from book.api import path_utils

SPEC_DIR = Path("book/integration/carton/spec")
BUNDLE_DIR = Path("book/integration/carton/bundle")
RELATIONSHIPS_DIR = BUNDLE_DIR / "relationships"
VIEWS_DIR = BUNDLE_DIR / "views"
CONTRACTS_DIR = BUNDLE_DIR / "contracts"
SCHEMAS_DIR = Path("book/integration/carton/schemas")

CARTON_SPEC = SPEC_DIR / "carton_spec.json"
FIXERS_SPEC = SPEC_DIR / "fixers.json"
INVARIANTS_SPEC = SPEC_DIR / "invariants.json"
MANIFEST_PATH = BUNDLE_DIR / "CARTON.json"


def repo_root() -> Path:
    return path_utils.find_repo_root(Path(__file__))


def ensure_absolute(path: str | Path, *, repo_root_path: Path | None = None) -> Path:
    root = repo_root_path or repo_root()
    return path_utils.ensure_absolute(path, repo_root=root)


def repo_relative(path: str | Path, *, repo_root_path: Path | None = None) -> str:
    root = repo_root_path or repo_root()
    return path_utils.to_repo_relative(path, repo_root=root)
