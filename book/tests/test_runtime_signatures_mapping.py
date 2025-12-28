import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SIGNATURES = ROOT / "book" / "graph" / "mappings" / "runtime" / "runtime_signatures.json"
BASELINE_REF = "book/world/sonoma-14.4.1-23E224-arm64/world.json"


def load_signatures():
    assert SIGNATURES.exists(), "missing runtime_signatures.json"
    data = json.loads(SIGNATURES.read_text())
    return data


def baseline_world():
    return json.loads((ROOT / BASELINE_REF).read_text()).get("world_id")


def test_signatures_present_and_host():
    data = load_signatures()
    meta = data.get("metadata") or {}
    assert meta.get("status") in {"ok", "partial", "brittle", "blocked"}
    assert "generated_at" not in meta
    assert meta.get("world_id") == baseline_world()
    sigs = data.get("signatures") or {}
    scenarios = data.get("scenarios") or {}
    expected = (data.get("expected_matrix") or {}).get("profiles") or {}
    assert sigs, "expected runtime signatures per-profile map"
    assert scenarios, "expected scenario-level signatures map"
    assert "adv:path_edges" in sigs
    assert "adv:path_edges:allow-tmp" in scenarios
    any_classified = False
    for prof in expected.values():
        for probe in prof.get("probes") or []:
            if probe.get("classification"):
                any_classified = True
                break
    assert any_classified, "expected_matrix rows should carry classifications"


def test_field2_summary_structure():
    data = load_signatures()
    summary = data.get("field2_summary") or {}
    profiles = summary.get("profiles") or {}
    assert "sys:bsd" in profiles and "sys:sample" in profiles
    for name, rec in profiles.items():
        assert "field2_entries" in rec
        assert "unknown_named" in rec
