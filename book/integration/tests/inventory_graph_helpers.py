from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Iterable, Tuple

from book.api import path_utils
from book.integration.carton.inventory import graph as inventory_graph


ROOT = path_utils.find_repo_root(Path(__file__))
GRAPH_PATH = ROOT / "book" / "integration" / "carton" / "bundle" / "relationships" / "inventory" / "inventory_graph.json"


def load_current_graph() -> Dict[str, object]:
    if not GRAPH_PATH.exists():
        raise AssertionError(f"missing inventory graph: {GRAPH_PATH}")
    return json.loads(GRAPH_PATH.read_text(encoding="utf-8"))


_EXPECTED_GRAPH: Dict[str, object] | None = None


def build_expected_graph() -> Dict[str, object]:
    global _EXPECTED_GRAPH
    if _EXPECTED_GRAPH is None:
        _EXPECTED_GRAPH = inventory_graph.build_inventory_graph(ROOT)
    return _EXPECTED_GRAPH


def artifacts_by_kind(doc: Dict[str, object], kinds: Iterable[str]) -> Dict[str, dict]:
    wanted = set(kinds)
    artifacts = doc.get("artifacts") or []
    out: Dict[str, dict] = {}
    for entry in artifacts:
        if not isinstance(entry, dict):
            continue
        if entry.get("kind") in wanted and entry.get("path"):
            out[str(entry["path"])] = entry
    return out


def diff_paths(expected: Dict[str, dict], current: Dict[str, dict]) -> Tuple[list[str], list[str]]:
    expected_paths = set(expected.keys())
    current_paths = set(current.keys())
    missing = sorted(expected_paths - current_paths)
    extra = sorted(current_paths - expected_paths)
    return missing, extra
