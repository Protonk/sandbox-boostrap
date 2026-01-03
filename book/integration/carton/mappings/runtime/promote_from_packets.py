#!/usr/bin/env python3
"""
Promote runtime evidence from promotion packets into runtime mappings.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[5]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from book.api import path_utils
from book.api.runtime.analysis.mapping import build as mapping_build

SCRIPT_ROOT = Path(__file__).resolve().parent
if str(SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPT_ROOT))

import promotion_packets
import generate_runtime_story
import generate_runtime_coverage
import generate_runtime_callout_oracle
import generate_runtime_signatures
import generate_op_runtime_summary
import generate_runtime_links

RUNTIME_CUTS_ROOT = ROOT / "book" / "integration" / "carton" / "bundle" / "relationships" / "mappings" / "runtime_cuts"
DEFAULT_RECEIPT_PATH = ROOT / "book" / "integration" / "carton" / "bundle" / "relationships" / "mappings" / "runtime" / "promotion_receipt.json"


def sha256_path(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _to_rel(path: Path) -> str:
    return str(path_utils.to_repo_relative(path_utils.ensure_absolute(path, ROOT), ROOT))


def _build_receipt(
    *,
    packet_set_path: Optional[Path],
    packet_paths: List[Path],
    used_packets: List[promotion_packets.PromotionPacket],
    rejected: List[Dict[str, Any]],
    world_id: str,
) -> Dict[str, Any]:
    inputs: List[str] = []
    input_hashes: Dict[str, str] = {}
    if packet_set_path:
        rel = _to_rel(packet_set_path)
        inputs.append(rel)
        if packet_set_path.exists():
            input_hashes[rel] = sha256_path(packet_set_path)
    rejected_by_path: Dict[str, Dict[str, Any]] = {str(r.get("path")): r for r in rejected if isinstance(r.get("path"), str)}
    considered: List[Dict[str, Any]] = []
    used_paths = {_to_rel(p.packet_path) for p in used_packets}
    for p in packet_paths:
        rel = _to_rel(p)
        entry: Dict[str, Any] = {"path": rel, "status": "rejected", "reasons": []}
        if p.exists():
            input_hashes[rel] = sha256_path(p)
            try:
                packet = promotion_packets.load_packet(p)
                entry["schema_version"] = packet.packet.get("schema_version")
                entry["channel"] = packet.run_manifest.get("channel")
                entry["run_id"] = packet.run_manifest.get("run_id")
                promotability = (packet.packet.get("promotability") or {}) if isinstance(packet.packet, dict) else {}
                entry["promotability"] = promotability or None
            except Exception as exc:
                entry["status"] = "rejected"
                entry["reasons"] = ["packet_load_error"]
                entry["error"] = str(exc)
            else:
                if rel in used_paths:
                    entry["status"] = "used"
                    entry["reasons"] = []
                rej = rejected_by_path.get(rel)
                if rej:
                    entry["status"] = "rejected"
                    entry["reasons"] = rej.get("reasons") or []
                    if rej.get("error"):
                        entry["error"] = rej.get("error")
        else:
            entry["status"] = "missing"
            entry["reasons"] = ["missing_packet"]
        considered.append(entry)
        inputs.append(rel)

    receipt = {
        "schema_version": promotion_packets.RECEIPT_SCHEMA_VERSION,
        "world_id": world_id,
        "inputs": inputs,
        "input_hashes": input_hashes,
        "packet_set": _to_rel(packet_set_path) if packet_set_path else None,
        "packets": {
            "considered": considered,
            "used": sorted(used_paths),
            "rejected": rejected,
        },
        "notes": "Receipt for runtime mapping promotion inputs; used packets are decision-stage promotable per their manifests/promotability blocks.",
    }
    return receipt


def build_runtime_cuts(packets: List[promotion_packets.PromotionPacket]) -> None:
    expected_matrix, world_id = promotion_packets.merge_expected_matrices(packets)
    observations = []
    for packet in packets:
        observations.extend(promotion_packets.load_observations(packet))

    cuts_root = path_utils.ensure_absolute(RUNTIME_CUTS_ROOT, ROOT)
    cuts_root.mkdir(parents=True, exist_ok=True)

    traces_dir = cuts_root / "traces"
    events_index, _ = mapping_build.write_traces(observations, traces_dir, world_id=world_id)
    events_index_path = cuts_root / "events_index.json"
    mapping_build.write_events_index(events_index, events_index_path)

    scenario_doc = mapping_build.build_scenarios(observations, expected_matrix, world_id=world_id)
    scenario_path = cuts_root / "scenarios.json"
    mapping_build.write_scenarios(scenario_doc, scenario_path)

    op_doc = mapping_build.build_ops(observations, world_id=world_id)
    op_path = cuts_root / "ops.json"
    mapping_build.write_ops(op_doc, op_path)

    idx_doc = mapping_build.build_indexes(scenario_doc, events_index)
    idx_path = cuts_root / "runtime_indexes.json"
    mapping_build.write_indexes(idx_doc, idx_path)

    manifest_doc = mapping_build.build_manifest(world_id, events_index_path, scenario_path, op_path)
    manifest_path = cuts_root / "runtime_manifest.json"
    mapping_build.write_manifest(manifest_doc, manifest_path)


def main() -> None:
    parser = argparse.ArgumentParser(description="Promote runtime mappings from promotion packets.")
    parser.add_argument("--packets", type=Path, action="append", help="Promotion packet paths")
    parser.add_argument("--packet-set", type=Path, help="Path to packet_set.json (preferred)")
    parser.add_argument("--receipt-out", type=Path, help="Where to write promotion_receipt.json")
    args = parser.parse_args()

    if args.packets and args.packet_set:
        raise SystemExit("--packets and --packet-set are mutually exclusive")

    packet_set_path = None
    allow_missing = True
    expected_world_id = None
    if args.packet_set:
        packet_set = promotion_packets.load_packet_set(args.packet_set)
        packet_set_path = packet_set.packet_set_path
        packet_paths = packet_set.packet_paths
        allow_missing = packet_set.allow_missing
        expected_world_id = packet_set.packet_set.get("world_id")
    elif args.packets:
        packet_paths = args.packets
    elif promotion_packets.DEFAULT_PACKET_SET_PATH.exists():
        packet_set = promotion_packets.load_packet_set(promotion_packets.DEFAULT_PACKET_SET_PATH)
        packet_set_path = packet_set.packet_set_path
        packet_paths = packet_set.packet_paths
        allow_missing = packet_set.allow_missing
        expected_world_id = packet_set.packet_set.get("world_id")
    else:
        packet_paths = promotion_packets.DEFAULT_PACKET_PATHS

    used: List[promotion_packets.PromotionPacket] = []
    rejected: List[Dict[str, Any]] = []
    packets: List[promotion_packets.PromotionPacket] = []
    for path in packet_paths:
        abs_path = path_utils.ensure_absolute(path, ROOT)
        if not abs_path.exists():
            if allow_missing:
                rejected.append({"path": _to_rel(abs_path), "reasons": ["missing_packet"]})
                continue
            raise SystemExit(f"missing promotion packet: {abs_path}")
        try:
            pkt = promotion_packets.load_packet(abs_path)
        except Exception as exc:
            rejected.append({"path": _to_rel(abs_path), "reasons": ["packet_load_error"], "error": str(exc)})
            continue
        packets.append(pkt)
        pkt_world_id = pkt.run_manifest.get("world_id")
        if expected_world_id and pkt_world_id and pkt_world_id != expected_world_id:
            rejected.append(
                {
                    "path": _to_rel(abs_path),
                    "reasons": ["world_id_mismatch"],
                    "error": f"expected {expected_world_id} but got {pkt_world_id}",
                }
            )
            continue
        try:
            promotion_packets.require_clean_manifest(pkt, str(pkt.packet_path))
        except Exception as exc:
            rejected.append({"path": _to_rel(abs_path), "reasons": ["not_promotable"], "error": str(exc)})
            continue
        used.append(pkt)

    world_ids = {p.run_manifest.get("world_id") for p in used if p.run_manifest.get("world_id")}
    if expected_world_id:
        world_id = expected_world_id
    elif len(world_ids) == 1:
        world_id = next(iter(world_ids))
    else:
        world_id = "unknown"
    receipt_out = path_utils.ensure_absolute(args.receipt_out or DEFAULT_RECEIPT_PATH, ROOT)
    receipt_out.parent.mkdir(parents=True, exist_ok=True)
    receipt = _build_receipt(
        packet_set_path=packet_set_path,
        packet_paths=[path_utils.ensure_absolute(p, ROOT) for p in packet_paths],
        used_packets=used,
        rejected=rejected,
        world_id=world_id,
    )
    receipt_out.write_text(json.dumps(receipt, indent=2, sort_keys=True))
    print(f"[+] wrote {receipt_out}")

    if not used:
        raise SystemExit("no promotable promotion packets found; see promotion_receipt.json")

    build_runtime_cuts(used)
    used_paths = [p.packet_path for p in used]
    generate_runtime_story.generate(packet_paths=used_paths)
    generate_runtime_coverage.generate(packet_paths=used_paths)
    generate_runtime_callout_oracle.generate(packet_paths=used_paths)
    generate_runtime_signatures.generate(packet_paths=used_paths)
    generate_op_runtime_summary.generate(packet_paths=used_paths)
    generate_runtime_links.generate(packet_paths=used_paths)


if __name__ == "__main__":
    main()
