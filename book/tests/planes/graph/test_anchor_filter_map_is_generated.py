import json
from pathlib import Path


from book.api import path_utils
ROOT = path_utils.find_repo_root(Path(__file__))


def load_json(path: Path):
    assert path.exists(), f"missing expected file: {path}"
    return json.loads(path.read_text())


def test_anchor_filter_map_is_pure_derived_view_and_deterministic():
    """
    Contract: `anchor_filter_map.json` is a strictly generated compatibility view.

    - It is a pure function of `anchor_ctx_filter_map.json` (no preservation of
      manual edits or runtime notes).
    - Regeneration must be byte-identical.
    - Each literal entry must carry `ctx_ids`.
    - A literal may be pinned only if all its ctx entries agree on one filter.
    """

    from book.graph.mappings.anchors import generate_anchor_filter_map as gen

    ctx_path = ROOT / "book" / "graph" / "mappings" / "anchors" / "anchor_ctx_filter_map.json"
    legacy_path = ROOT / "book" / "graph" / "mappings" / "anchors" / "anchor_filter_map.json"

    ctx_doc = load_json(ctx_path)
    expected_doc = gen.build_legacy_anchor_filter_map(ctx_doc, baseline_world_id=gen._baseline_world_id())
    expected_text = gen.render_json(expected_doc)
    actual_text = legacy_path.read_text()
    assert actual_text == expected_text, "anchor_filter_map.json drifted; regenerate via generate_anchor_maps.py"

    meta = expected_doc.get("metadata") or {}
    assert isinstance(meta, dict)
    assert meta.get("anchor_ctx_map") == "book/graph/mappings/anchors/anchor_ctx_filter_map.json"
    assert meta.get("generated_by") == "book/graph/mappings/anchors/generate_anchor_filter_map.py"

    ctx_entries = (ctx_doc.get("entries") or {}) if isinstance(ctx_doc, dict) else {}
    assert isinstance(ctx_entries, dict) and ctx_entries, "expected non-empty ctx map entries"

    for literal, entry in expected_doc.items():
        if literal == "metadata":
            continue
        assert isinstance(entry, dict), f"legacy entry for {literal!r} must be a dict"
        ctx_ids = entry.get("ctx_ids")
        assert isinstance(ctx_ids, list) and ctx_ids, f"{literal!r} missing ctx_ids"
        assert all(isinstance(cid, str) and cid.startswith("ctx:") for cid in ctx_ids), f"{literal!r} bad ctx_ids"
        assert all(cid in ctx_entries for cid in ctx_ids), f"{literal!r} ctx_ids not present in ctx map"

        pinned = entry.get("filter_id") is not None or entry.get("filter_name") is not None
        if pinned:
            assert isinstance(entry.get("filter_id"), int)
            assert isinstance(entry.get("filter_name"), str)
            for cid in ctx_ids:
                cent = ctx_entries.get(cid) or {}
                assert cent.get("filter_id") == entry["filter_id"]
                assert cent.get("filter_name") == entry["filter_name"]
        else:
            # If every ctx entry is resolved and agrees, legacy must have pinned it.
            resolved = []
            for cid in ctx_ids:
                cent = ctx_entries.get(cid) or {}
                resolved.append((cent.get("filter_id"), cent.get("filter_name")))
            all_resolved = all(isinstance(fid, int) and isinstance(fname, str) for fid, fname in resolved)
            all_same = len({pair for pair in resolved if isinstance(pair[0], int) and isinstance(pair[1], str)}) == 1
            assert not (all_resolved and all_same), f"{literal!r} legacy entry should be pinned but is blocked"

