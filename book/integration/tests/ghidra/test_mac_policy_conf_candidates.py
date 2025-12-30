import json
from pathlib import Path


def test_mac_policy_conf_candidates_schema():
    path = Path("book/dumps/ghidra/out/14.4.1-23E224/sandbox-kext-conf-scan/mac_policy_conf_candidates.json")
    assert path.exists(), "mac_policy_conf_candidates.json missing; run sandbox-kext-conf-scan task"
    data = json.loads(path.read_text())
    assert "meta" in data and "candidates" in data
    candidates = data["candidates"]
    # Allow empty candidates but require schema keys when present.
    for cand in candidates:
        assert "address" in cand and "slots" in cand
        slots = cand["slots"]
        for key in [
            "name",
            "fullname",
            "labelnames",
            "labelname_count",
            "ops",
            "loadtime_flags",
            "field_or_label_slot",
            "runtime_flags",
        ]:
            assert key in slots
