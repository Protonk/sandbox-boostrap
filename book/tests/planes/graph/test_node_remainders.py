import json
from pathlib import Path

from book.api.profile import ingestion as pi

from book.api import path_utils
ROOT = path_utils.find_repo_root(Path(__file__))
CONTRACT = ROOT / "book" / "graph" / "concepts" / "validation" / "out" / "static" / "node_remainders.json"


def compute_remainder(path: Path, stride: int = 12) -> tuple[int, str]:
    blob = path.read_bytes()
    header = pi.parse_header(pi.ProfileBlob(bytes=blob, source=str(path)))
    sections = pi.slice_sections(pi.ProfileBlob(bytes=blob, source=str(path)), header)
    nodes = sections.nodes
    canonical_len = (len(nodes) // stride) * stride
    remainder = nodes[canonical_len:]
    return len(nodes), remainder.hex()


def test_node_remainders_match_contract():
    data = json.loads(CONTRACT.read_text())
    profiles = data.get("profiles") or {}
    assert profiles, "node remainder contract empty"
    for name, entry in profiles.items():
        source = ROOT / entry["source"]
        nodes_len, remainder_hex = compute_remainder(source, stride=entry["record_size_bytes"])
        assert nodes_len == entry["nodes_length"], f"nodes length mismatch for {name}"
        assert remainder_hex == entry["remainder_hex"], f"remainder hex mismatch for {name}"
