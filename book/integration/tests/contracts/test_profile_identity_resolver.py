import hashlib
import json
from pathlib import Path

from book.api.profile import identity as identity_mod


from book.api import path_utils
ROOT = path_utils.find_repo_root(Path(__file__))
BASELINE = ROOT / "book" / "world" / "sonoma-14.4.1-23E224-arm64" / "world.json"
TAG_LAYOUTS = ROOT / "book" / "evidence" / "graph" / "mappings" / "tag_layouts" / "tag_layouts.json"
DIGESTS = ROOT / "book" / "evidence" / "graph" / "mappings" / "system_profiles" / "digests.json"
STATIC_CHECKS = ROOT / "book" / "evidence" / "graph" / "mappings" / "system_profiles" / "static_checks.json"
ATTESTATIONS = ROOT / "book" / "evidence" / "graph" / "mappings" / "system_profiles" / "attestations.json"
ATTESTATIONS_DIR = ROOT / "book" / "evidence" / "graph" / "mappings" / "system_profiles" / "attestations"


def _load(path: Path) -> dict:
    assert path.exists(), f"missing mapping: {path}"
    return json.loads(path.read_text())


def test_canonical_system_profile_identity_resolves():
    resolved = identity_mod.resolve_all_canonical_system_profiles()
    assert set(resolved.keys()) == {"sys:airlock", "sys:bsd", "sys:sample"}
    for pid, ident in resolved.items():
        assert ident.profile_id == pid
        assert ident.blob_path.endswith(".sb.bin")
        assert (ROOT / ident.blob_path).exists()
        assert ident.static_checks_entry.get("path") == ident.blob_path
        assert ident.attestation_entry.get("source") == ident.blob_path
        assert ident.attestation_entry.get("canonical_profile_id") == pid
        assert ident.attestation_entry.get("role") == "canonical-system-profile"


def test_system_profile_attestations_are_compiled_blobs_only():
    data = _load(ATTESTATIONS)
    for entry in data.get("attestations") or []:
        source = entry.get("source")
        assert isinstance(source, str) and source.endswith(".sb.bin")


def test_attestations_jsonl_directory_matches_manifest():
    data = _load(ATTESTATIONS)
    expected = data.get("metadata", {}).get("attestation_count")
    assert isinstance(expected, int) and expected > 0
    jsonl_files = sorted(ATTESTATIONS_DIR.glob("*.jsonl"))
    assert len(jsonl_files) == expected


def test_tag_layout_hash_semantics_are_explicit_and_consistent():
    world_id = _load(BASELINE).get("world_id")
    tag_layouts_sha256 = hashlib.sha256(TAG_LAYOUTS.read_bytes()).hexdigest()

    static_meta = _load(STATIC_CHECKS).get("metadata") or {}
    attest_meta = _load(ATTESTATIONS).get("metadata") or {}

    assert static_meta.get("world_id") == world_id
    assert attest_meta.get("world_id") == world_id

    assert static_meta.get("tag_layout_hash_method") == "tag_set"
    assert attest_meta.get("tag_layout_hash_method") == "tag_set"
    assert static_meta.get("tag_layout_hash") == attest_meta.get("tag_layout_hash")

    assert static_meta.get("tag_layouts_file_sha256") == tag_layouts_sha256
    assert attest_meta.get("tag_layouts_file_sha256") == tag_layouts_sha256
