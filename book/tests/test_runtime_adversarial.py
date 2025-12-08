import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
BASE_DIR = REPO_ROOT / "book" / "experiments" / "runtime-adversarial"
OUT_DIR = BASE_DIR / "out"
WORLD_PATH = REPO_ROOT / "book" / "world" / "sonoma-14.4.1-23E224-arm64" / "world-baseline.json"


def load_json(path: Path):
    assert path.exists(), f"missing required artifact: {path}"
    return json.loads(path.read_text())


def test_adversarial_artifacts_present_and_annotated():
    world = load_json(WORLD_PATH)["id"]
    expected_matrix = load_json(OUT_DIR / "expected_matrix.json")
    runtime_results = load_json(OUT_DIR / "runtime_results.json")
    mismatch_summary = load_json(OUT_DIR / "mismatch_summary.json")
    impact_map = load_json(OUT_DIR / "impact_map.json")

    assert expected_matrix.get("world") == world
    assert mismatch_summary.get("world") == world
    assert set(expected_matrix.get("profiles", {})) == {
        "adv:struct_flat",
        "adv:struct_nested",
        "adv:path_edges",
        "adv:mach_simple_allow",
        "adv:mach_simple_variants",
        "adv:mach_local_literal",
        "adv:mach_local_regex",
    }
    # Shapes must stay aligned.
    assert set(runtime_results.keys()) == set(expected_matrix.get("profiles", {}).keys())
    # Every mismatch must be annotated in impact_map to force deliberate triage.
    for mismatch in mismatch_summary.get("mismatches") or []:
        eid = mismatch.get("expectation_id")
        assert eid in impact_map, f"unannotated mismatch for {eid}"
