from __future__ import annotations

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
    re.compile(r"book/experiments/.+/out/runtime_results\.json"),
    re.compile(r"book/experiments/.+/out/runtime_events\.normalized\.json"),
    re.compile(r"book/experiments/.+/out/expected_matrix\.json"),
    re.compile(r"book/experiments/.+/out/run_manifest\.json"),
    re.compile(r"book/experiments/.+/out/baseline_results\.json"),
]


def test_runtime_mappings_use_promotion_packets():
    for path in MAPPING_TARGETS:
        text = path.read_text()
        rel = path.relative_to(ROOT)
        for pattern in FORBIDDEN_EXPERIMENT_OUT:
            assert not pattern.search(text), f"{rel} contains direct experiment out path: {pattern.pattern}"


def test_field2_atlas_allow_legacy_guard():
    atlas = ROOT / "book" / "experiments" / "field2-atlas" / "atlas_runtime.py"
    text = atlas.read_text()
    assert "--allow-legacy" in text, "field2-atlas runtime should require explicit allow-legacy"
    assert "promotion_packet.json missing" in text, "field2-atlas runtime should reject missing promotion packet"
