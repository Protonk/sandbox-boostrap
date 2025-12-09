import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def load_json(path: Path):
    assert path.exists(), f"missing expected file: {path}"
    return json.loads(path.read_text())


def test_anchor_filter_alignment_with_anchor_hits():
    """
    Guardrail: mapped anchors in anchor_filter_map.json must be backed by
    anchor_hits.json for this world, and the pinned filter_id must appear
    among the observed field2 values for those anchors.
    """
    amap = load_json(ROOT / "book" / "graph" / "mappings" / "anchors" / "anchor_filter_map.json")
    hits = load_json(ROOT / "book" / "experiments" / "probe-op-structure" / "out" / "anchor_hits.json")

    anchors_checked = 0
    for anchor, entry in amap.items():
        if not isinstance(entry, dict):
            continue
        if entry.get("status") == "blocked":
            continue
        filter_id = entry.get("filter_id")
        sources = entry.get("sources") or []
        if filter_id is None or not sources:
            continue

        observed: set[int] = set()
        for src in sources:
            # anchor_hits keys are "probe:..." or "sys:...", matching the source ids.
            profile_hits = hits.get(src)
            if not profile_hits:
                continue
            for ah in profile_hits.get("anchors") or []:
                if ah.get("anchor") != anchor:
                    continue
                for val in ah.get("field2_values") or []:
                    observed.add(val)

        # Only enforce alignment when we have at least one observation.
        assert observed, f"no anchor_hits observations for mapped anchor {anchor!r}"
        anchors_checked += 1

        # The pinned filter_id must appear among observed field2 values.
        assert filter_id in observed, (
            f"mapped filter_id {filter_id} for anchor {anchor!r} "
            f"not present in field2_values observed in anchor_hits.json"
        )

        # Observed values should be reflected in the mapping's recorded field2_values.
        mapped_vals = set(entry.get("field2_values") or [])
        assert observed <= mapped_vals, (
            f"anchor_filter_map field2_values for {anchor!r} "
            f"do not cover all observed field2 values: observed={sorted(observed)}, "
            f"mapped={sorted(mapped_vals)}"
        )

    assert anchors_checked > 0, "expected to check at least one mapped anchor"

