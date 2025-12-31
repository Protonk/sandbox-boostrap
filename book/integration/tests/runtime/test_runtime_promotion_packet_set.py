import json
from pathlib import Path

from book.api import path_utils


ROOT = path_utils.find_repo_root(Path(__file__))
PACKET_SET = ROOT / "book" / "graph" / "mappings" / "runtime" / "packet_set.json"
PROMOTION_RECEIPT = ROOT / "book" / "graph" / "mappings" / "runtime" / "promotion_receipt.json"


def load_json(path: Path) -> dict:
    assert path.exists(), f"missing required file: {path}"
    return json.loads(path.read_text())


def test_promotion_receipt_aligns_with_packet_set():
    packet_set = load_json(PACKET_SET)
    receipt = load_json(PROMOTION_RECEIPT)

    expected = set(packet_set.get("packets") or [])
    considered = receipt.get("packets", {}).get("considered") or []
    considered_paths = {entry.get("path") for entry in considered if entry.get("path")}

    errors: list[str] = []
    missing = sorted(expected - considered_paths)
    extra = sorted(considered_paths - expected)
    if missing:
        errors.append("missing packets in promotion receipt: " + ", ".join(missing))
    if extra:
        errors.append("unexpected packets in promotion receipt: " + ", ".join(extra))

    expected_packet_set = path_utils.to_repo_relative(PACKET_SET, repo_root=ROOT)
    if receipt.get("packet_set") != str(expected_packet_set):
        errors.append(f"promotion receipt packet_set mismatch: {receipt.get('packet_set')}")

    assert not errors, "\n".join(errors)
