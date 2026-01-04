import json
from pathlib import Path

import pytest

from book.api import path_utils

ROOT = path_utils.find_repo_root(Path(__file__))
WORLD_ID = "sonoma-14.4.1-23E224-arm64-dyld-a3a840f9"


def load_json(path: Path):
    assert path.exists(), f"missing required file: {path}"
    return json.loads(path.read_text())


def repo_rel(path) -> str:
    absolute = path_utils.ensure_absolute(path, ROOT)
    return path_utils.to_repo_relative(absolute, ROOT)


def build_anchor_hits(path: Path):
    hits_doc = load_json(path)
    anchor_hits = {}
    for profile_name, payload in hits_doc.items():
        for anchor_entry in payload.get("anchors") or []:
            name = anchor_entry.get("anchor")
            if not name:
                continue
            anchor_hits.setdefault(name, []).append((profile_name, anchor_entry))
    return anchor_hits


def test_anchor_field2_map_metadata_and_presence():
    anchor_map_path = ROOT / "book" / "integration" / "carton" / "bundle" / "relationships" / "mappings" / "anchors" / "anchor_field2_map.json"
    hits_path = (
        ROOT
        / "book"
        / "evidence"
        / "experiments"
        / "field2-final-final"
        / "probe-op-structure"
        / "out"
        / "anchor_hits.json"
    )
    anchor_map = load_json(anchor_map_path)
    metadata = anchor_map.get("metadata") or {}
    assert metadata.get("world_id") == WORLD_ID
    assert metadata.get("status") in {"partial", "ok"}
    metadata_inputs = {repo_rel(p) for p in (metadata.get("inputs") or [])}
    assert repo_rel(hits_path) in metadata_inputs
    assert "source_jobs" in metadata

    anchor_hits = build_anchor_hits(hits_path)
    anchors = {a for a in anchor_map if a != "metadata"}
    assert anchors, "expected anchors in anchor_field2_map"

    for anchor in anchors:
        assert anchor in anchor_hits, f"{anchor} missing from anchor_hits"
        profiles = anchor_map[anchor].get("profiles") or {}
        role = anchor_map[anchor].get("role", "exploratory")
        hits_profiles = {prof for prof, _ in anchor_hits[anchor]}
        for prof in profiles:
            assert prof in hits_profiles, f"{anchor} profile {prof} missing from anchor_hits"
        map_field2 = set()
        for observations in profiles.values():
            for obs in observations or []:
                map_field2.update(obs.get("field2_values") or [])
        hits_field2 = set()
        for _, entry in anchor_hits[anchor]:
            hits_field2.update(entry.get("field2_values") or [])
        assert map_field2.issubset(hits_field2), f"{anchor} field2 values not witnessed in anchor_hits"
        if role == "contract":
            assert map_field2, f"{anchor} (contract) missing field2 evidence"
            assert len(hits_profiles) >= 2, f"{anchor} (contract) needs multiple witnesses"
            node_indices = set()
            for observations in profiles.values():
                for obs in observations or []:
                    node_indices.update(obs.get("node_indices") or [])
            assert node_indices, f"{anchor} (contract) missing node indices"


def test_carton_anchor_field2_aligns_with_map_and_hits():
    anchor_index_path = ROOT / "book" / "integration" / "carton" / "bundle" / "relationships" / "anchor_field2.json"
    anchor_map_path = ROOT / "book" / "integration" / "carton" / "bundle" / "relationships" / "mappings" / "anchors" / "anchor_field2_map.json"
    hits_path = (
        ROOT
        / "book"
        / "evidence"
        / "experiments"
        / "field2-final-final"
        / "probe-op-structure"
        / "out"
        / "anchor_hits.json"
    )

    index_doc = load_json(anchor_index_path)
    index_meta = index_doc.get("metadata") or {}
    assert index_meta.get("world_id") == WORLD_ID
    assert index_meta.get("status") in {"partial", "ok"}
    metadata_inputs = {repo_rel(p) for p in (index_meta.get("inputs") or [])}
    for required in [anchor_map_path, hits_path]:
        required_input = repo_rel(required)
        assert required_input in metadata_inputs, f"missing input {required_input}"

    anchor_map = load_json(anchor_map_path)
    anchor_hits = build_anchor_hits(hits_path)

    anchors = index_doc.get("anchors") or {}
    assert anchors, "expected anchors in anchor_index"
    assert set(anchors.keys()) == {a for a in anchor_map if a != "metadata"}

    for anchor, entry in anchors.items():
        assert anchor in anchor_hits, f"{anchor} missing from anchor_hits"
        map_entry = anchor_map[anchor]
        role = map_entry.get("role", "exploratory")
        hits_profiles = {prof for prof, _ in anchor_hits[anchor]}
        assert set(entry.get("profiles") or []).issubset(hits_profiles)
        # field2 values in the index must be witnessed in anchor_hits
        hits_field2 = set()
        for _, hit in anchor_hits[anchor]:
            hits_field2.update(hit.get("field2_values") or [])
        assert set(entry.get("field2_values") or []).issubset(hits_field2), f"{anchor} field2 values not in hits"
        assert entry.get("status") in {"partial", "ok"}
        if role == "contract":
            assert entry.get("field2_values"), f"{anchor} (contract) missing field2 evidence"
            assert len(entry.get("sources") or []) >= 2, f"{anchor} (contract) needs multiple sources"
            assert entry.get("node_indices"), f"{anchor} (contract) missing node indices"
