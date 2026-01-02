import json
from pathlib import Path

import pytest


from book.api import path_utils

ROOT = path_utils.find_repo_root(Path(__file__))
CONTRACT = ROOT / "book" / "evidence" / "graph" / "mappings" / "system_profiles" / "header_contract.json"


@pytest.mark.smoke
def test_header_contract_matches_blobs():
    data = json.loads(CONTRACT.read_text())
    profiles = data.get("profiles", {})
    assert profiles, "no profiles in header contract"
    for name, entry in profiles.items():
        source = ROOT / entry["source"]
        blob = source.read_bytes()
        words = [int.from_bytes(blob[i : i + 2], "little") for i in range(0, min(len(blob), 16), 2)]
        assert len(blob) == entry["length"], f"length mismatch for {name}"
        assert words == entry["header_words"], f"header words mismatch for {name}"
        assert words[1] == entry["op_count_word"], f"op_count word mismatch for {name}"
        assert words[0] == entry["maybe_flags_word"], f"maybe_flags word mismatch for {name}"
