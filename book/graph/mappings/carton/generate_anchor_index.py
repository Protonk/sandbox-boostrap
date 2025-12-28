import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from book.api import evidence_tiers  # noqa: E402
from book.api import world as world_mod  # noqa: E402


def load_json(path: Path):
    return json.loads(path.read_text())


def baseline_world_id() -> str:
    data, resolution = world_mod.load_world(repo_root=ROOT)
    return world_mod.require_world_id(data, world_path=resolution.entry.world_path)


def assert_world_compatible(baseline_world: str, other: dict | str | None, label: str) -> None:
    if not other:
        return
    other_world = other.get("world_id") if isinstance(other, dict) else other
    if other_world and other_world != baseline_world:
        raise RuntimeError(f"world_id mismatch for {label}: baseline {baseline_world} vs {other_world}")


def main():
    anchors_path = ROOT / "book" / "graph" / "mappings" / "anchors" / "anchor_field2_map.json"
    hits_path = ROOT / "book" / "experiments" / "probe-op-structure" / "out" / "anchor_hits.json"
    out_path = ROOT / "book" / "graph" / "mappings" / "carton" / "anchor_index.json"

    anchors_doc = load_json(anchors_path)
    hits_doc = load_json(hits_path)
    world_id = baseline_world_id()
    assert_world_compatible(world_id, anchors_doc.get("metadata"), "anchor_field2_map")

    # Build a quick lookup of anchor -> observations from anchor_hits.
    anchor_hits = {}
    for profile_name, payload in hits_doc.items():
        for anchor_entry in payload.get("anchors") or []:
            name = anchor_entry.get("anchor")
            if not name:
                continue
            anchor_hits.setdefault(name, []).append((profile_name, anchor_entry))

    anchors = {}
    for anchor, entry in anchors_doc.items():
        if anchor == "metadata":
            continue
        profiles = entry.get("profiles") or {}
        field2_values = set()
        node_indices = set()
        sources = []
        for profile_name, observations in profiles.items():
            sources.append(profile_name)
            for obs in observations or []:
                field2_values.update(obs.get("field2_values") or [])
                node_indices.update(obs.get("node_indices") or [])
        anchors[anchor] = {
            "field2_values": sorted(field2_values),
            "node_indices": sorted(node_indices),
            "profiles": sorted(set(sources)),
            "status": entry.get("status", "partial"),
            # Default to exploratory; callers can down-select to stricter roles later.
            "role": entry.get("role", "exploratory"),
            "sources": sorted(set(sources)),
        }
        if anchor not in anchor_hits:
            anchors[anchor]["warning"] = "anchor not present in anchor_hits; keep partial"

    doc = {
        "metadata": {
            "world_id": world_id,
            "status": anchors_doc.get("metadata", {}).get("status", "partial"),
            "tier": evidence_tiers.evidence_tier_for_artifact(
                path=out_path,
                tier="mapped",
            ),
            "inputs": [
                "book/graph/mappings/anchors/anchor_field2_map.json",
                "book/experiments/probe-op-structure/out/anchor_hits.json",
            ],
            "source_jobs": ["experiment:probe-op-structure"],
            "notes": "CARTON-facing anchor → field2 hints. Structural only; roles default to exploratory.",
        },
        "anchors": anchors,
    }

    out_path.write_text(json.dumps(doc, indent=2) + "\n")


if __name__ == "__main__":
    main()
