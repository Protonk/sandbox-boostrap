from __future__ import annotations

import json
from pathlib import Path

from book.api import path_utils


def test_runtime_promotion_packet_set_is_present_and_valid():
    repo_root = path_utils.find_repo_root(Path(__file__))
    packet_set_path = repo_root / "book/graph/mappings/runtime/packet_set.json"
    assert packet_set_path.exists(), f"missing packet_set.json: {packet_set_path}"

    doc = json.loads(packet_set_path.read_text(encoding="utf-8"))
    assert doc.get("schema_version") == "runtime.packet_set.v0.1"
    assert doc.get("world_id") == "sonoma-14.4.1-23E224-arm64-dyld-2c0602c5"
    assert doc.get("allow_missing") is True
    assert doc.get("packets") == [
        "book/experiments/runtime-checks/out/promotion_packet.json",
        "book/experiments/runtime-adversarial/out/promotion_packet.json",
        "book/experiments/hardened-runtime/out/promotion_packet.json",
        "book/experiments/anchor-filter-map/out/promotion_packet.json",
        "book/experiments/anchor-filter-map/iokit-class/out/promotion_packet.json",
    ]
