#!/usr/bin/env python3
"""
Generate op_runtime_summary.json from promotion packets.
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
from book.api.runtime import op_summary as runtime_op_summary

SCRIPT_ROOT = Path(__file__).resolve().parent
if str(SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPT_ROOT))

import promotion_packets

OUT = ROOT / "book" / "graph" / "mappings" / "runtime" / "op_runtime_summary.json"


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


def generate(packet_paths: List[Path] | None = None) -> Path:
    world_id = baseline_world()
    packets = promotion_packets.load_packets(packet_paths or promotion_packets.DEFAULT_PACKET_PATHS, allow_missing=True)
    for packet in packets:
        promotion_packets.require_clean_manifest(packet, str(packet.packet_path))

    observations = []
    for packet in packets:
        observations.extend(promotion_packets.load_observations(packet))

    inputs: List[str] = []
    input_hashes: Dict[str, str] = {}
    for packet in packets:
        rel = path_utils.to_repo_relative(packet.packet_path, ROOT)
        inputs.append(rel)
        input_hashes[rel] = sha256_path(packet.packet_path)

    summary = runtime_op_summary.build_op_runtime_summary(
        observations,
        world_id=world_id,
        inputs=inputs,
        input_hashes=input_hashes,
        source_jobs=["promotion_packet"],
        notes="Op-level summary derived from promotion packets (decision-stage only).",
    )

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(summary, indent=2))
    print(f"[+] wrote {OUT}")
    return OUT


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate op_runtime_summary.json from promotion packets.")
    parser.add_argument("--packets", type=Path, action="append", help="Promotion packet paths")
    args = parser.parse_args()
    generate(packet_paths=args.packets)


if __name__ == "__main__":
    main()
