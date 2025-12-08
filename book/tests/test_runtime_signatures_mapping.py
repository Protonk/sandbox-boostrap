import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SIGNATURES = ROOT / "book" / "graph" / "mappings" / "runtime" / "runtime_signatures.json"
BASELINE_REF = "book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json"
GOLDEN = {"bucket4:v1_read", "bucket5:v11_read_subpath", "runtime:metafilter_any"}


def load_signatures():
    assert SIGNATURES.exists(), "missing runtime_signatures.json"
    data = json.loads(SIGNATURES.read_text())
    return data


def baseline_world():
    return json.loads((ROOT / BASELINE_REF).read_text()).get("world_id")


def test_signatures_present_and_host():
    data = load_signatures()
    meta = data.get("metadata") or {}
    assert meta.get("status") == "ok"
    assert "generated_at" not in meta
    assert meta.get("world_id") == baseline_world()
    sigs = data.get("signatures") or {}
    for key in GOLDEN:
        assert key in sigs, f"missing signature for {key}"


def test_field2_summary_structure():
    data = load_signatures()
    summary = data.get("field2_summary") or {}
    profiles = summary.get("profiles") or {}
    assert "sys:bsd" in profiles and "sys:sample" in profiles
    for name, rec in profiles.items():
        assert "field2_entries" in rec
        assert "unknown_named" in rec
