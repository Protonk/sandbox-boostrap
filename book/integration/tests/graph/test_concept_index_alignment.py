import json
from pathlib import Path

from book.api import path_utils

ROOT = path_utils.find_repo_root(Path(__file__))
CONCEPT_MAP = ROOT / "book" / "evidence" / "syncretic" / "concepts" / "concept_map.json"
CONCEPT_INDEX = ROOT / "book" / "integration" / "carton" / "bundle" / "views" / "concept_index.json"
MANIFEST = ROOT / "book" / "integration" / "carton" / "bundle" / "CARTON.json"


def test_concept_index_keys_are_known_concepts():
    cmap = json.loads(CONCEPT_MAP.read_text())
    known_ids = {entry["id"] for entry in cmap}
    idx = json.loads(CONCEPT_INDEX.read_text())
    concept_keys = set((idx.get("concepts") or {}).keys())
    assert concept_keys <= known_ids, f"concept_index has unknown concepts: {concept_keys - known_ids}"


def test_concept_index_paths_are_manifested_and_exist():
    idx = json.loads(CONCEPT_INDEX.read_text())
    manifest = json.loads(MANIFEST.read_text())
    manifest_paths = {entry["path"] for entry in manifest.get("artifacts", [])}
    for entries in (idx.get("concepts") or {}).values():
        for entry in entries:
            path = entry["path"]
            assert (ROOT / path).exists(), f"concept_index path missing: {path}"
            assert path in manifest_paths, f"concept_index path not listed in manifest: {path}"
