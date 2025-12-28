import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def load_json(path: Path):
    assert path.exists(), f"missing expected file: {path}"
    return json.loads(path.read_text())


def test_vfs_path_canonicalization_map_is_generated_and_deterministic():
    """
    Contract: `book/graph/mappings/vfs_canonicalization/*` is generated from promotion packets.

    - `path_canonicalization_map.json` and `promotion_receipt.json` are a pure
      function of `packet_set.json` and the referenced promotion packets.
    - Regeneration is byte-identical (stable ordering + formatting).
    """

    from book.graph.mappings.vfs_canonicalization import generate_path_canonicalization_map as gen

    mapping_root = ROOT / "book" / "graph" / "mappings" / "vfs_canonicalization"
    packet_set_path = mapping_root / "packet_set.json"
    mapping_path = mapping_root / "path_canonicalization_map.json"
    receipt_path = mapping_root / "promotion_receipt.json"

    packet_set = load_json(packet_set_path)
    packet_paths = [Path(p) for p in (packet_set.get("packets") or [])]
    allow_missing = bool(packet_set.get("allow_missing", True))
    expected_world_id = packet_set.get("world_id")

    expected_mapping, expected_receipt = gen.generate_docs(
        packet_set_path=packet_set_path,
        packet_paths=packet_paths,
        allow_missing=allow_missing,
        expected_world_id=expected_world_id,
    )

    assert mapping_path.read_text() == gen.render_json(expected_mapping)
    assert receipt_path.read_text() == gen.render_json(expected_receipt)

    meta = expected_mapping.get("metadata") or {}
    assert isinstance(meta, dict)
    assert "status" not in meta, "vfs mapping should not use metadata.status (tiering is handled elsewhere)"

