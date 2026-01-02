from __future__ import annotations

import json
import re
from pathlib import Path

from book.api import path_utils


ROOT = path_utils.find_repo_root(Path(__file__))

MAPPING_TARGETS = [
    ROOT / "book" / "graph" / "mappings" / "runtime" / "generate_runtime_story.py",
    ROOT / "book" / "graph" / "mappings" / "runtime" / "generate_runtime_coverage.py",
    ROOT / "book" / "graph" / "mappings" / "runtime" / "generate_runtime_callout_oracle.py",
    ROOT / "book" / "graph" / "mappings" / "runtime" / "generate_runtime_signatures.py",
    ROOT / "book" / "graph" / "mappings" / "runtime" / "promote_from_packets.py",
]

FORBIDDEN_EXPERIMENT_OUT = [
    re.compile(r"book/experiments/.+/out/runtime_results\\.json"),
    re.compile(r"book/experiments/.+/out/runtime_events\\.normalized\\.json"),
    re.compile(r"book/experiments/.+/out/expected_matrix\\.json"),
    re.compile(r"book/experiments/.+/out/run_manifest\\.json"),
    re.compile(r"book/experiments/.+/out/baseline_results\\.json"),
]


def test_runtime_promotion_contracts():
    failures: list[str] = []

    for path in MAPPING_TARGETS:
        text = path.read_text()
        rel = path.relative_to(ROOT)
        for pattern in FORBIDDEN_EXPERIMENT_OUT:
            if pattern.search(text):
                failures.append(f"{rel} contains direct experiment out path: {pattern.pattern}")

    atlas = (
        ROOT
        / "book"
        / "experiments"
        / "field2-final-final"
        / "field2-atlas"
        / "atlas_runtime.py"
    )
    atlas_text = atlas.read_text()
    if "packet_utils.resolve_packet_context" not in atlas_text:
        failures.append("book/experiments/field2-final-final/field2-atlas/atlas_runtime.py missing packet-only resolver")
    if "allow-legacy" in atlas_text:
        failures.append("book/experiments/field2-final-final/field2-atlas/atlas_runtime.py still mentions allow-legacy")

    packet_set_path = ROOT / "book" / "graph" / "mappings" / "runtime" / "packet_set.json"
    if not packet_set_path.exists():
        failures.append(f"missing packet_set.json: {packet_set_path}")
    else:
        doc = json.loads(packet_set_path.read_text(encoding="utf-8"))
        if doc.get("schema_version") != "runtime.packet_set.v0.1":
            failures.append("packet_set.json schema_version mismatch")
        if doc.get("world_id") != "sonoma-14.4.1-23E224-arm64-dyld-2c0602c5":
            failures.append("packet_set.json world_id mismatch")
        if doc.get("allow_missing") is not True:
            failures.append("packet_set.json allow_missing must be true")
        expected_packets = [
            "book/experiments/runtime-final-final/evidence/packets/runtime-checks.promotion_packet.json",
            "book/experiments/runtime-final-final/evidence/packets/runtime-adversarial.promotion_packet.json",
            "book/experiments/runtime-final-final/evidence/packets/hardened-runtime.promotion_packet.json",
            "book/experiments/runtime-final-final/evidence/packets/anchor-filter-map.promotion_packet.json",
            "book/experiments/runtime-final-final/evidence/packets/anchor-filter-map.iokit-class.promotion_packet.json",
        ]
        if doc.get("packets") != expected_packets:
            failures.append("packet_set.json packets list mismatch")

    assert not failures, "runtime promotion contract failures:\n" + "\n".join(failures)
