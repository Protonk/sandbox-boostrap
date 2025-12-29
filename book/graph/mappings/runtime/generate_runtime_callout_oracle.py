#!/usr/bin/env python3
"""
Generate runtime_callout_oracle.json from promotion packet runtime events.

This is the seatbelt-callout lane: markers only, kept separate from syscall outcomes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from book.api import path_utils
from book.api import world as world_mod
from book.api.runtime.core import models
from book.api.runtime.mapping import views as runtime_views

OUT = ROOT / "book/graph/mappings/runtime/runtime_callout_oracle.json"

SCRIPT_ROOT = Path(__file__).resolve().parent
if str(SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPT_ROOT))

import promotion_packets


def load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text())


def sha256_path(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def baseline_world() -> str:
    data, resolution = world_mod.load_world(repo_root=ROOT)
    return world_mod.require_world_id(data, world_path=resolution.entry.world_path)


def load_runtime_observations(packets: List[promotion_packets.PromotionPacket]) -> List[models.RuntimeObservation]:
    observations: List[models.RuntimeObservation] = []
    for packet in packets:
        observations.extend(promotion_packets.load_observations(packet))
    return observations


def generate(packet_paths: List[Path] | None = None) -> Path:
    world_id = baseline_world()
    packets = promotion_packets.load_packets(packet_paths or promotion_packets.DEFAULT_PACKET_PATHS, allow_missing=True)
    for packet in packets:
        promotion_packets.require_clean_manifest(packet, str(packet.packet_path))

    observations = load_runtime_observations(packets)
    doc = runtime_views.build_callout_oracle(observations)

    inputs: List[Path] = []
    for packet in packets:
        inputs.append(packet.packet_path)
        if packet.paths.get("runtime_events"):
            inputs.append(packet.paths["runtime_events"])
        if packet.paths.get("run_manifest"):
            inputs.append(packet.paths["run_manifest"])
    input_rel = [path_utils.to_repo_relative(p, ROOT) for p in inputs]
    input_hashes = {path_utils.to_repo_relative(p, ROOT): sha256_path(p) for p in inputs if p.exists()}

    meta = doc.get("meta", {})
    meta.update(
        {
            "world_id": world_id,
            "inputs": input_rel,
            "input_hashes": input_hashes,
            "source_jobs": ["promotion_packet"],
            "status": meta.get("status", "partial"),
            "notes": "Seatbelt-callout markers derived from promotion packet runtime_events.",
        }
    )
    if not doc.get("rows"):
        meta["notes"] = meta.get("notes", "") + " No callout markers observed in inputs."
    doc["meta"] = meta

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(doc, indent=2, sort_keys=True))
    print(f"[+] wrote {OUT}")
    return OUT


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate runtime callout oracle from promotion packets.")
    parser.add_argument("--packets", type=Path, action="append", help="Promotion packet paths")
    args = parser.parse_args()
    generate(packet_paths=args.packets)


if __name__ == "__main__":
    main()
