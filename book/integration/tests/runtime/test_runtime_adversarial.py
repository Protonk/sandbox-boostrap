import json
from pathlib import Path


from book.api import path_utils
from book.integration.tests.runtime.runtime_bundle_helpers import load_bundle_json

REPO_ROOT = path_utils.find_repo_root(Path(__file__))
BASE_DIR = REPO_ROOT / "book" / "evidence" / "experiments" / "runtime-final-final" / "suites" / "runtime-adversarial"
OUT_DIR = BASE_DIR / "out"
WORLD_PATH = REPO_ROOT / "book" / "world" / "sonoma-14.4.1-23E224-arm64" / "world.json"


def load_json(path: Path):
    assert path.exists(), f"missing required artifact: {path}"
    return json.loads(path.read_text())


def test_adversarial_artifacts_present_and_annotated():
    world = load_json(WORLD_PATH)
    world_id = world.get("world_id") or world.get("id")
    expected_matrix = load_bundle_json(OUT_DIR, "expected_matrix.json")
    runtime_results = load_bundle_json(OUT_DIR, "runtime_results.json")
    mismatch_summary = load_bundle_json(OUT_DIR, "mismatch_summary.json")
    path_witnesses = load_bundle_json(OUT_DIR, "path_witnesses.json")

    assert expected_matrix.get("world_id") == world_id
    assert mismatch_summary.get("world_id") == world_id
    assert path_witnesses.get("world_id") == world_id
    assert set(expected_matrix.get("profiles", {})) == {
        "adv:struct_flat",
        "adv:struct_nested",
        "adv:path_edges",
        "adv:path_edges_private",
        "adv:path_alias",
        "adv:mount_relative_path",
        "adv:mach_simple_allow",
        "adv:mach_simple_variants",
        "adv:mach_local_literal",
        "adv:mach_local_regex",
        "adv:net_outbound_allow",
        "adv:net_outbound_deny",
        "adv:xattr",
        "adv:file_mode",
        "adv:flow_divert_require_all_tcp",
        "adv:flow_divert_partial_tcp",
    }
    # Shapes must stay aligned.
    assert set(runtime_results.keys()) == set(expected_matrix.get("profiles", {}).keys())

    records = path_witnesses.get("records") or []
    scenario_edges = [
        rec
        for rec in records
        if rec.get("lane") == "scenario" and rec.get("profile_id") == "adv:path_edges"
    ]
    assert scenario_edges, "expected path_witnesses for adv:path_edges probes"
