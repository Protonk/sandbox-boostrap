import json
from pathlib import Path


def _parse_hex(val: str) -> int:
    if not isinstance(val, str):
        raise ValueError(f"expected hex string, got {type(val)}")
    if val.startswith("0x-"):
        return -int(val[2:], 16)
    return int(val, 16)


def test_mac_policy_conf_candidates_static_scan():
    path = Path("book/evidence/dumps/ghidra/out/14.4.1-23E224/sandbox-kext-conf-scan/mac_policy_conf_candidates.json")
    assert path.exists(), "mac_policy_conf_candidates.json missing; run sandbox-kext-conf-scan"
    data = json.loads(path.read_text())

    meta = data.get("meta", {})
    assert "probe_points" in meta and "bytes_scanned" in meta, "missing scan bookkeeping in meta"
    assert meta.get("candidate_count", -1) >= 0, "candidate_count missing"

    candidates = data.get("candidates", [])
    assert candidates, "expected at least one candidate to confirm scan executed"

    for cand in candidates:
        slots = cand.get("slots", {})
        # labelname_count bound
        lcount = slots.get("labelname_count")
        assert isinstance(lcount, int) and 0 <= lcount <= 32, "labelname_count outside expected range"
        # pointer-like fields parse as hex
        for key in ["name", "fullname", "labelnames", "ops", "field_or_label_slot", "extra0", "extra1"]:
            val = slots.get(key)
            assert isinstance(val, str), f"{key} missing"
            _parse_hex(val)

        # strings are absent on this world (ok-negative anchor)
        strings = cand.get("string_values", {}) or {}
        assert strings.get("name") is None and strings.get("fullname") is None
