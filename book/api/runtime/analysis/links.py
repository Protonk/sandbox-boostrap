"""
Runtime links mapping loader and helpers.

This module keeps runtime_links.json easy to consume without requiring callers
to understand its internal layout.

Links are the connective tissue between runtime evidence and the
static vocab/profiles. Keeping them in one place reduces cross-module coupling.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from book.api import path_utils


REPO_ROOT = path_utils.find_repo_root(Path(__file__))
# Default bundle runtime links location; override for tests as needed.
RUNTIME_LINKS_PATH = REPO_ROOT / "book" / "integration" / "carton" / "bundle" / "relationships" / "mappings" / "runtime" / "runtime_links.json"


def load_runtime_links(path: Optional[Path] = None) -> Dict[str, Any]:
    """Load runtime_links.json (default: bundle runtime_links path)."""
    path = path_utils.ensure_absolute(path or RUNTIME_LINKS_PATH, REPO_ROOT)
    return json.loads(path.read_text())


def list_linked_profiles(links_doc: Dict[str, Any]) -> list[str]:
    """Return sorted profile ids present in the runtime links doc."""
    profiles = links_doc.get("profiles") or {}
    return sorted(profiles.keys())


def list_linked_expectations(links_doc: Dict[str, Any]) -> list[str]:
    """Return sorted expectation ids present in the runtime links doc."""
    expectations = links_doc.get("expectations") or {}
    return sorted(expectations.keys())


def resolve_profile_link(links_doc: Dict[str, Any], profile_id: str) -> Optional[Dict[str, Any]]:
    """Return the link record for a profile id, or None when absent."""
    profiles = links_doc.get("profiles") or {}
    entry = profiles.get(profile_id)
    if not isinstance(entry, dict):
        return None
    return entry


def resolve_expectation_link(links_doc: Dict[str, Any], expectation_id: str) -> Optional[Dict[str, Any]]:
    """Return the link record for an expectation id, or None when absent."""
    expectations = links_doc.get("expectations") or {}
    entry = expectations.get(expectation_id)
    if not isinstance(entry, dict):
        return None
    return entry
