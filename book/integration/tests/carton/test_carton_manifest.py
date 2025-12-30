import json
from pathlib import Path

from book.api import path_utils
from book.integration.carton import build_manifest

ROOT = path_utils.find_repo_root(Path(__file__))
SPEC = ROOT / "book" / "integration" / "carton" / "carton_spec.json"
MANIFEST = ROOT / "book" / "integration" / "carton" / "CARTON.json"
BASELINE_REF = "book/world/sonoma-14.4.1-23E224-arm64/world.json"


def _canonical_digest(doc: dict) -> str:
    return build_manifest._sha256_canonical_json(doc)


def test_carton_manifest_matches_spec_and_world():
    assert MANIFEST.exists(), "missing CARTON manifest"
    manifest = json.loads(MANIFEST.read_text())
    spec = json.loads(SPEC.read_text())

    assert manifest.get("schema_version") == build_manifest.MANIFEST_SCHEMA_VERSION
    assert "generated_at" not in manifest
    assert manifest.get("spec_path") == "book/integration/carton/carton_spec.json"
    assert manifest.get("spec_sha256") == _canonical_digest(spec)

    baseline_world = json.loads((ROOT / BASELINE_REF).read_text()).get("world_id")
    assert manifest.get("world_id") == baseline_world
    assert spec.get("world_id") == baseline_world

    spec_entries = {entry["id"]: entry for entry in spec.get("artifacts", [])}
    manifest_entries = {entry["id"]: entry for entry in manifest.get("artifacts", [])}

    assert set(spec_entries.keys()) == set(manifest_entries.keys())
    for artifact_id, spec_entry in spec_entries.items():
        manifest_entry = manifest_entries[artifact_id]
        assert manifest_entry.get("path") == spec_entry.get("path")
        assert manifest_entry.get("role") == spec_entry.get("role")
        assert manifest_entry.get("digest_mode") == spec_entry.get("hash_mode")


def test_carton_manifest_deterministic():
    live = build_manifest.build_manifest_doc(spec_path=SPEC, repo_root=ROOT)
    manifest = json.loads(MANIFEST.read_text())
    assert _canonical_digest(live) == _canonical_digest(manifest)
