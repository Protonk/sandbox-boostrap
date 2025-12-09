"""
Helpers for consistent repo-root path handling.

These utilities keep runtime artifacts and validation outputs repo-relative while
still resolving paths to absolutes when executing probes or compiling SBPL.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Iterable, Sequence, Union

Pathish = Union[str, Path]


@lru_cache()
def find_repo_root(start: Path | None = None) -> Path:
    """
    Walk upward from `start` (or this file) until we find a directory that
    looks like the repo root.
    """
    cur = (start or Path(__file__)).resolve()
    agents_root: Path | None = None
    for candidate in [cur] + list(cur.parents):
        if (candidate / ".git").exists():
            return candidate
        if (candidate / "AGENTS.md").exists():
            agents_root = candidate
    if agents_root:
        return agents_root
    raise RuntimeError("Unable to locate repository root")


def ensure_absolute(path: Pathish, repo_root: Path | None = None) -> Path:
    """Return an absolute Path, resolving relative paths against the repo root."""
    p = Path(path)
    if p.is_absolute():
        return p.resolve()
    root = repo_root or find_repo_root()
    return (root / p).resolve()


def to_repo_relative(path: Pathish, repo_root: Path | None = None) -> str:
    """Return a repo-relative string if possible, otherwise the absolute string."""
    p = Path(path).resolve()
    root = (repo_root or find_repo_root()).resolve()
    try:
        return str(p.relative_to(root))
    except ValueError:
        return str(p)


def relativize_command(parts: Sequence[Pathish], repo_root: Path | None = None) -> list[str]:
    """Convert any repo-root-prefixed command argv entries to repo-relative form."""
    rel: list[str] = []
    for part in parts:
        try:
            rel.append(to_repo_relative(Path(part), repo_root))
        except Exception:
            rel.append(str(part))
    return rel


def relativize_paths(paths: Iterable[Pathish], repo_root: Path | None = None) -> list[str]:
    """Apply `to_repo_relative` across a list/iterable of paths."""
    return [to_repo_relative(p, repo_root) for p in paths]


def absolute_paths(paths: Iterable[Pathish], repo_root: Path | None = None) -> list[Path]:
    """Resolve a collection of paths against the repo root."""
    return [ensure_absolute(p, repo_root) for p in paths]
