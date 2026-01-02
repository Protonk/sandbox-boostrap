import json
from pathlib import Path


from book.api import path_utils
ROOT = path_utils.find_repo_root(Path(__file__))
OUT_DIR = (
    ROOT
    / "book"
    / "experiments"
    / "field2-final-final"
    / "probe-op-structure"
    / "out"
)


def test_analysis_contains_expected_profiles():
    data = json.loads((OUT_DIR / "analysis.json").read_text())
    # Ensure key probes and system profiles are present
    for key in [
        "probe:v1_file_require_any",
        "probe:v4_network_socket_require_all",
        "probe:v7_file_network_combo",
        "sys:bsd",
        "sys:sample",
    ]:
        assert key in data, f"{key} missing from analysis.json"
    # Sanity check some expected field2 names still appear
    net_field2 = {entry["name"] for entry in data["probe:v4_network_socket_require_all"]["field2"]}
    assert "remote" in net_field2 or "local" in net_field2


def test_anchor_hits_present_even_if_empty_nodes():
    data = json.loads((OUT_DIR / "anchor_hits.json").read_text())
    # Anchors should be recorded for probes even if node_indices are empty
    for key in ["probe:v1_file_require_any", "probe:v3_mach_global_local", "probe:v4_network_socket_require_all"]:
        assert key in data, f"{key} missing from anchor_hits.json"
        anchors = data[key].get("anchors") or []
        assert anchors, f"{key} has no anchors recorded"
        # Ensure offsets field exists
        for anch in anchors:
            assert "offsets" in anch
            assert "field2_values" in anch
