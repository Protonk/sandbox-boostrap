import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DIGESTS = ROOT / "book" / "graph" / "mappings" / "system_profiles" / "digests.json"
BASELINE_REF = "book/world/sonoma-14.4.1-23E224-arm64/world.json"


def baseline_world():
    return json.loads((ROOT / BASELINE_REF).read_text()).get("world_id")


def test_digests_mapping_shape():
    """Canonical digests pin contract shape + world pointer and start at ok."""
    assert DIGESTS.exists(), "missing system profile digests mapping"
    data = json.loads(DIGESTS.read_text())
    meta = data.get("metadata") or {}
    assert meta.get("world_id") == baseline_world()
    assert meta.get("contract_fields") == [
        "contract_version",
        "sbpl_hash",
        "blob_sha256",
        "blob_size",
        "op_table_hash",
        "op_table_len",
        "tag_counts",
        "tag_layout_hash",
        "world_id",
    ]
    assert meta.get("status") == "ok"
    assert "source_jobs" in meta
    canonical = meta.get("canonical_profiles") or {}
    # Basic profiles present
    profiles = data.get("profiles") or {}
    expected = {"sys:airlock", "sys:bsd", "sys:sample"}
    assert set(canonical.keys()) == expected, "canonical set should stay fixed to the bedrock trio"
    for key in expected:
        assert key in profiles, f"missing digest for {key}"
        assert key in canonical, f"missing canonical status for {key}"
        assert canonical[key].get("status") == "ok"
        body = profiles[key]
        assert body.get("world_id") == baseline_world()
        assert body.get("status") == "ok"
        contract = body.get("contract") or {}
        assert contract.get("contract_version") == 2
        for field in meta.get("contract_fields") or []:
            assert field in contract, f"missing contract field {field} for {key}"
        assert contract.get("world_id") == baseline_world()
        assert not body.get("drift"), f"unexpected drift recorded for {key}"
        # Mapping world pointer, contract world pointer, and baseline must stay in lockstep.
        assert body.get("world_id") == contract.get("world_id") == meta.get("world_id")
