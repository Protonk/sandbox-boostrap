import json
from pathlib import Path


from book.api import path_utils
ROOT = path_utils.find_repo_root(Path(__file__))
LINKS = ROOT / "book" / "graph" / "mappings" / "runtime" / "runtime_links.json"
OPS = ROOT / "book" / "graph" / "mappings" / "vocab" / "ops.json"
SYSTEM_DIGESTS = ROOT / "book" / "graph" / "mappings" / "system_profiles" / "digests.json"
BASELINE = ROOT / "book" / "world" / "sonoma-14.4.1-23E224-arm64" / "world.json"


def _load_json(path: Path) -> dict:
    assert path.exists(), f"missing {path}"
    return json.loads(path.read_text())


def test_runtime_links_meta():
    data = _load_json(LINKS)
    meta = data.get("meta") or {}
    world_id = _load_json(BASELINE).get("world_id")
    assert meta.get("world_id") == world_id
    assert meta.get("tier") == "mapped"
    assert meta.get("status") in {"ok", "partial", "brittle", "blocked"}
    assert meta.get("schema_version") == "runtime-links.v0.1"
    inputs = meta.get("inputs") or []
    input_hashes = meta.get("input_hashes") or {}
    assert inputs, "expected inputs list"
    assert set(inputs) == set(input_hashes.keys())
    assert all(not Path(p).is_absolute() for p in inputs)


def test_runtime_links_paths_resolve():
    data = _load_json(LINKS)
    links = data.get("links") or {}
    required = [
        "ops_vocab",
        "ops_coverage",
        "tag_layouts",
        "system_profile_digests",
        "runtime_signatures",
        "op_runtime_summary",
        "runtime_callout_oracle",
    ]
    for key in required:
        path = links.get(key)
        assert path, f"missing links.{key}"
        resolved = ROOT / path
        assert resolved.exists(), f"missing {key} at {resolved}"


def test_runtime_links_expectations_and_profiles():
    data = _load_json(LINKS)
    ops_vocab = _load_json(OPS).get("ops") or []
    ops_index = {entry.get("name"): entry.get("id") for entry in ops_vocab}

    expectations = data.get("expectations") or {}
    profiles = data.get("profiles") or {}
    assert expectations, "expected runtime_links expectations"
    assert profiles, "expected runtime_links profiles"

    for exp_id, exp in expectations.items():
        op_name = exp.get("operation")
        assert op_name in ops_index, f"unknown op in expectation {exp_id}"
        assert exp.get("op_id") == ops_index.get(op_name)
        profile_id = exp.get("profile_id")
        assert profile_id in profiles, f"unknown profile in expectation {exp_id}"

    for profile_id, entry in profiles.items():
        expected_ops = entry.get("expected_ops") or []
        for op_name in expected_ops:
            assert op_name in ops_index, f"unknown op in profile {profile_id}"
        op_ids = entry.get("op_ids") or {}
        for op_name, op_id in op_ids.items():
            assert ops_index.get(op_name) == op_id
        for exp_id in entry.get("expectation_ids") or []:
            assert expectations.get(exp_id, {}).get("profile_id") == profile_id


def test_runtime_links_system_profiles_consistent():
    data = _load_json(LINKS)
    digests = _load_json(SYSTEM_DIGESTS).get("profiles") or {}
    for profile_id, entry in (data.get("profiles") or {}).items():
        digest_id = entry.get("system_profile_digest_id")
        if not digest_id:
            continue
        assert digest_id in digests
        digest = digests[digest_id]
        observed = digest.get("observed") or {}
        linked = (entry.get("system_profile_digest") or {}).get("observed") or {}
        if observed.get("blob_sha256") and linked.get("blob_sha256"):
            assert observed.get("blob_sha256") == linked.get("blob_sha256")
