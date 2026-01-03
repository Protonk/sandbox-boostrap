import json
from pathlib import Path


from book.api import path_utils

ROOT = path_utils.find_repo_root(Path(__file__))
BASELINE = ROOT / "book" / "world" / "sonoma-14.4.1-23E224-arm64" / "world.json"
STATIC_CHECKS = ROOT / "book" / "integration" / "carton" / "bundle" / "relationships" / "mappings" / "system_profiles" / "static_checks.json"
ATTESTATIONS = ROOT / "book" / "integration" / "carton" / "bundle" / "relationships" / "mappings" / "system_profiles" / "attestations.json"


def load_json(path: Path):
    assert path.exists(), f"missing mapping: {path}"
    return json.loads(path.read_text())


def test_system_profile_mappings_have_metadata():
    world_id = load_json(BASELINE).get("world_id")

    static_doc = load_json(STATIC_CHECKS)
    static_meta = static_doc.get("metadata") or {}
    assert static_meta.get("world_id") == world_id
    assert static_meta.get("tag_layout_hash")
    assert static_meta.get("inputs")

    attest_doc = load_json(ATTESTATIONS)
    attest_meta = attest_doc.get("metadata") or {}
    assert attest_meta.get("world_id") == world_id
    assert attest_meta.get("tag_layout_hash")
    assert attest_meta.get("attestation_count") == len(attest_doc.get("attestations") or [])
    assert attest_meta.get("inputs")
