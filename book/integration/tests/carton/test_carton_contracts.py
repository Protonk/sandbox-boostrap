import json
from pathlib import Path

from book.api import path_utils
from book.integration.carton import bundle

ROOT = path_utils.find_repo_root(Path(__file__))


def _canonical_digest(doc: dict) -> str:
    return bundle._sha256_canonical_json(doc)


def test_contract_snapshots_match_sources():
    world_id, _ = bundle._baseline_world(ROOT)
    expected = bundle.build_contracts(repo_root=ROOT, world_id=world_id)
    for rel_path, doc in expected.items():
        path = path_utils.ensure_absolute(rel_path, repo_root=ROOT)
        assert path.exists(), f"missing contract file: {rel_path}"
        current = json.loads(path.read_text())
        assert _canonical_digest(current) == _canonical_digest(doc)
