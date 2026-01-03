#!/usr/bin/env python3
"""
Generate a VFS canonicalization mapping slice from promotion packets.

Inputs:
- `packet_set.json` in the mappings bundle (preferred), or explicit `--packets` args.

Outputs (in the mappings bundle):
- `promotion_receipt.json`
- `path_canonicalization_map.json`

This generator is intentionally conservative:
- It only uses packets that are decision-stage promotable (`launchd_clean` +
  promotability block says `promotable_decision_stage=true`).
- It refuses to "infer" canonicalization from denied probes (no FD == no
  kernel-reported path spelling witness).
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

MAPPING_ROOT = (
    ROOT
    / "book"
    / "integration"
    / "carton"
    / "bundle"
    / "relationships"
    / "mappings"
    / "vfs_canonicalization"
)

DEFAULT_PACKET_SET_PATH = MAPPING_ROOT / "packet_set.json"
DEFAULT_RECEIPT_PATH = MAPPING_ROOT / "promotion_receipt.json"
DEFAULT_OUT_PATH = MAPPING_ROOT / "path_canonicalization_map.json"

MAP_SCHEMA_VERSION = "vfs_canonicalization.path_canonicalization_map.v0.1"
RECEIPT_SCHEMA_VERSION = "vfs_canonicalization.promotion_receipt.v0.1"


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8", errors="ignore"))

def render_json(doc: Dict[str, Any]) -> str:
    return json.dumps(doc, indent=2, sort_keys=True) + "\n"

def _sha256_path(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _to_rel(path: Path) -> str:
    return str(path_utils.to_repo_relative(path_utils.ensure_absolute(path, ROOT), ROOT))


def _load_packet_set(path: Path) -> tuple[Dict[str, Any], List[Path], bool]:
    doc = _load_json(path)
    schema = doc.get("schema_version")
    if schema != "runtime.packet_set.v0.1":
        raise ValueError(f"unexpected packet_set schema_version: {schema!r} ({path})")
    raw_paths = doc.get("packets") or []
    if not isinstance(raw_paths, list) or not all(isinstance(p, str) for p in raw_paths):
        raise ValueError(f"packet_set.packets must be list[str] ({path})")
    allow_missing = bool(doc.get("allow_missing", True))
    paths = [path_utils.ensure_absolute(Path(p), ROOT) for p in raw_paths]
    return doc, paths, allow_missing


def _packet_promotable(packet: Dict[str, Any], run_manifest: Dict[str, Any]) -> tuple[bool, List[str]]:
    promotability = packet.get("promotability") or {}
    promotable = promotability.get("promotable_decision_stage")
    reasons = promotability.get("reasons") or []
    if run_manifest.get("channel") != "launchd_clean":
        return False, ["not_clean_channel"]
    if promotable is not True:
        # VFS canonicalization can still be supported by baseline-only evidence
        # (unsandboxed FD path observation) even when the decision-stage lane is
        # not promotable (for example: missing apply-preflight record).
        return False, ["baseline_only"] + [str(r) for r in reasons]
    return True, []


def _load_packet(packet_path: Path) -> tuple[Dict[str, Any], Dict[str, Any]]:
    packet = _load_json(packet_path)
    run_manifest_path = packet.get("run_manifest")
    if not isinstance(run_manifest_path, str):
        raise ValueError("packet missing run_manifest")
    run_manifest = _load_json(path_utils.ensure_absolute(Path(run_manifest_path), ROOT))
    return packet, run_manifest


def _load_path_witnesses(packet: Dict[str, Any]) -> Dict[str, Any]:
    path_witnesses_path = packet.get("path_witnesses")
    if not isinstance(path_witnesses_path, str):
        raise ValueError("packet missing path_witnesses")
    return _load_json(path_utils.ensure_absolute(Path(path_witnesses_path), ROOT))


def _dedupe_observations(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Dedupe to a stable, reviewable set of path observations.

    We key off the "witness payload" (lane + requested/observed spellings),
    keeping one representative per unique tuple.
    """

    seen = set()
    out: List[Dict[str, Any]] = []
    for row in records:
        key = (
            row.get("lane"),
            row.get("operation"),
            row.get("requested_path"),
            row.get("observed_path"),
            row.get("observed_path_nofirmlink"),
            row.get("observed_path_source"),
            row.get("observed_path_nofirmlink_source"),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
    out.sort(
        key=lambda r: (
            str(r.get("lane") or ""),
            str(r.get("operation") or ""),
            str(r.get("requested_path") or ""),
            str(r.get("observed_path") or ""),
            str(r.get("observed_path_nofirmlink") or ""),
        )
    )
    return out


def _build_map(*, used_packets: List[Path], records: List[Dict[str, Any]], world_id: str) -> Dict[str, Any]:
    inputs = {_to_rel(p): _sha256_path(p) for p in used_packets if p.exists()}
    witness_records = [
        r
        for r in records
        if isinstance(r, dict) and (r.get("observed_path") or r.get("observed_path_nofirmlink"))
    ]
    return {
        "schema_version": MAP_SCHEMA_VERSION,
        "world_id": world_id,
        "metadata": {
            "generated_by": _to_rel(Path(__file__)),
            "inputs": inputs,
            "dropped_non_witness_records": len(records) - len(witness_records),
        },
        "observations": _dedupe_observations(witness_records),
    }


def _build_receipt(
    *,
    packet_set_path: Optional[Path],
    packet_paths: List[Path],
    used_packets: List[Path],
    used_kinds: Dict[str, str],
    used_reasons: Dict[str, List[str]],
    rejected: List[Dict[str, Any]],
    world_id: str,
) -> Dict[str, Any]:
    inputs: List[str] = []
    input_hashes: Dict[str, str] = {}
    if packet_set_path:
        rel = _to_rel(packet_set_path)
        inputs.append(rel)
        if packet_set_path.exists():
            input_hashes[rel] = _sha256_path(packet_set_path)
    for p in packet_paths:
        rel = _to_rel(p)
        inputs.append(rel)
        if p.exists():
            input_hashes[rel] = _sha256_path(p)

    used_rel = {_to_rel(p) for p in used_packets}
    considered: List[Dict[str, Any]] = []
    rejected_by_path = {r.get("path"): r for r in rejected if isinstance(r.get("path"), str)}
    for p in packet_paths:
        rel = _to_rel(p)
        entry: Dict[str, Any] = {"path": rel, "status": "rejected", "reasons": []}
        if rel in used_rel:
            entry["status"] = "used"
            entry["acceptance"] = used_kinds.get(rel)
            entry["reasons"] = used_reasons.get(rel) or []
        rej = rejected_by_path.get(rel)
        if rej and entry["status"] != "used":
            entry["reasons"] = rej.get("reasons") or []
            if rej.get("error"):
                entry["error"] = rej.get("error")
        considered.append(entry)

    return {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "world_id": world_id,
        "inputs": inputs,
        "input_hashes": input_hashes,
        "considered_packets": considered,
    }

def generate_docs(
    *,
    packet_set_path: Optional[Path],
    packet_paths: List[Path],
    allow_missing: bool,
    expected_world_id: Optional[str],
) -> tuple[Dict[str, Any], Dict[str, Any]]:
    used_packets: List[Path] = []
    used_kinds: Dict[str, str] = {}
    used_reasons: Dict[str, List[str]] = {}
    rejected: List[Dict[str, Any]] = []
    records: List[Dict[str, Any]] = []
    world_id = expected_world_id or "unknown"

    for packet_path in packet_paths:
        abs_path = path_utils.ensure_absolute(packet_path, ROOT)
        rel = _to_rel(abs_path)
        if not abs_path.exists():
            if allow_missing:
                rejected.append({"path": rel, "reasons": ["missing_packet"]})
                continue
            raise FileNotFoundError(f"missing promotion packet: {abs_path}")
        try:
            packet, run_manifest = _load_packet(abs_path)
        except Exception as exc:
            rejected.append({"path": rel, "reasons": ["packet_load_error"], "error": str(exc)})
            continue
        pkt_world = run_manifest.get("world_id")
        if expected_world_id and pkt_world and pkt_world != expected_world_id:
            rejected.append(
                {"path": rel, "reasons": ["world_id_mismatch"], "error": f"expected {expected_world_id} got {pkt_world}"}
            )
            continue
        if pkt_world and world_id in {"unknown", None}:
            world_id = pkt_world

        promotable, reasons = _packet_promotable(packet, run_manifest)
        try:
            witness_doc = _load_path_witnesses(packet)
        except Exception as exc:
            rejected.append({"path": rel, "reasons": ["missing_path_witnesses"], "error": str(exc)})
            continue
        lane_filter = None if promotable else "baseline"
        selected: List[Dict[str, Any]] = []
        for row in witness_doc.get("records") or []:
            if not isinstance(row, dict):
                continue
            if lane_filter and row.get("lane") != lane_filter:
                continue
            selected.append(row)
        if not selected:
            rejected.append({"path": rel, "reasons": ["no_witness_records"] + reasons})
            continue

        records.extend(selected)
        used_packets.append(abs_path)
        used_kinds[rel] = "decision_stage" if promotable else "baseline_only"
        used_reasons[rel] = reasons

    receipt = _build_receipt(
        packet_set_path=packet_set_path,
        packet_paths=[path_utils.ensure_absolute(p, ROOT) for p in packet_paths],
        used_packets=used_packets,
        used_kinds=used_kinds,
        used_reasons=used_reasons,
        rejected=rejected,
        world_id=world_id,
    )
    mapping_doc = _build_map(used_packets=used_packets, records=records, world_id=world_id)
    return mapping_doc, receipt


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate VFS canonicalization mapping from promotion packets.")
    parser.add_argument("--packets", type=Path, action="append", help="Promotion packet paths")
    parser.add_argument("--packet-set", type=Path, help="Path to packet_set.json (preferred)")
    parser.add_argument("--out", type=Path, help="Where to write path_canonicalization_map.json")
    parser.add_argument("--receipt-out", type=Path, help="Where to write promotion_receipt.json")
    args = parser.parse_args()

    packet_set_path = None
    allow_missing = True
    expected_world_id = None
    if args.packet_set:
        packet_set_path = path_utils.ensure_absolute(args.packet_set, ROOT)
        packet_set, packet_paths, allow_missing = _load_packet_set(packet_set_path)
        expected_world_id = packet_set.get("world_id")
    elif args.packets:
        packet_paths = [path_utils.ensure_absolute(p, ROOT) for p in args.packets]
    else:
        packet_set_path = DEFAULT_PACKET_SET_PATH
        packet_set, packet_paths, allow_missing = _load_packet_set(packet_set_path)
        expected_world_id = packet_set.get("world_id")

    mapping_doc, receipt = generate_docs(
        packet_set_path=packet_set_path,
        packet_paths=packet_paths,
        allow_missing=allow_missing,
        expected_world_id=expected_world_id,
    )

    receipt_out = path_utils.ensure_absolute(args.receipt_out or DEFAULT_RECEIPT_PATH, ROOT)
    receipt_out.parent.mkdir(parents=True, exist_ok=True)
    receipt_out.write_text(render_json(receipt))

    out_path = path_utils.ensure_absolute(args.out or DEFAULT_OUT_PATH, ROOT)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(render_json(mapping_doc))


if __name__ == "__main__":
    main()
