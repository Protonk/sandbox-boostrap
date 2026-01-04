#!/usr/bin/env python3
"""
Helpers for loading runtime promotion packets as mapping inputs.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from book.api import path_utils
from book.api.runtime.contracts import models

REPO_ROOT = path_utils.find_repo_root(Path(__file__))

PACKET_SET_SCHEMA_VERSION = "runtime.packet_set.v0.1"
RECEIPT_SCHEMA_VERSION = "runtime.promotion_receipt.v0.1"

DEFAULT_PACKET_PATHS = [
    REPO_ROOT / "book/evidence/experiments/runtime-final-final/evidence/packets/runtime-checks.promotion_packet.json",
    REPO_ROOT / "book/evidence/experiments/runtime-final-final/evidence/packets/runtime-adversarial.promotion_packet.json",
    REPO_ROOT / "book/evidence/experiments/runtime-final-final/evidence/packets/hardened-runtime.promotion_packet.json",
    REPO_ROOT / "book/evidence/experiments/runtime-final-final/evidence/packets/anchor-filter-map.promotion_packet.json",
    REPO_ROOT / "book/evidence/experiments/runtime-final-final/evidence/packets/anchor-filter-map.iokit-class.promotion_packet.json",
]

DEFAULT_PACKET_SET_PATH = REPO_ROOT / "book/integration/carton/bundle/relationships/mappings/runtime/packet_set.json"

REQUIRED_FIELDS = ("run_manifest", "expected_matrix", "runtime_results", "runtime_events")
OPTIONAL_FIELDS = ("baseline_results", "oracle_results", "mismatch_packets", "summary", "impact_map")
LEGACY_PATH_REWRITES = (
    ("book/evidence/graph/concepts/validation/", "book/evidence/carton/validation/"),
    ("book/evidence/graph/concepts/", "book/evidence/carton/concepts/"),
    ("book/evidence/graph/mappings/", "book/integration/carton/bundle/relationships/mappings/"),
)


@dataclass(frozen=True)
class PromotionPacket:
    packet_path: Path
    packet: Dict[str, Any]
    paths: Dict[str, Path]
    run_manifest: Dict[str, Any]

@dataclass(frozen=True)
class PacketSet:
    packet_set_path: Path
    packet_set: Dict[str, Any]
    packet_paths: List[Path]
    allow_missing: bool


def _load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"missing input: {path}")
    return json.loads(path.read_text())

def _rewrite_legacy_paths(value: Any) -> Any:
    if isinstance(value, str):
        updated = value
        for old, new in LEGACY_PATH_REWRITES:
            if old in updated:
                updated = updated.replace(old, new)
        return updated
    if isinstance(value, list):
        return [_rewrite_legacy_paths(item) for item in value]
    if isinstance(value, dict):
        return {key: _rewrite_legacy_paths(val) for key, val in value.items()}
    return value

def load_packet_set(packet_set_path: Path) -> PacketSet:
    packet_set_path = path_utils.ensure_absolute(packet_set_path, REPO_ROOT)
    doc = _load_json(packet_set_path)
    schema = doc.get("schema_version")
    if schema != PACKET_SET_SCHEMA_VERSION:
        raise ValueError(f"unexpected packet_set schema_version: {schema!r} ({packet_set_path})")
    raw_paths = doc.get("packets") or []
    if not isinstance(raw_paths, list) or not all(isinstance(p, str) for p in raw_paths):
        raise ValueError(f"packet_set.packets must be a list[str] ({packet_set_path})")
    allow_missing = bool(doc.get("allow_missing", True))
    packet_paths = [path_utils.ensure_absolute(Path(p), REPO_ROOT) for p in raw_paths]
    return PacketSet(
        packet_set_path=packet_set_path,
        packet_set=doc,
        packet_paths=packet_paths,
        allow_missing=allow_missing,
    )


def load_packet(packet_path: Path) -> PromotionPacket:
    packet_path = path_utils.ensure_absolute(packet_path, REPO_ROOT)
    packet = _load_json(packet_path)
    paths: Dict[str, Path] = {}
    missing = []
    for key in REQUIRED_FIELDS:
        value = packet.get(key)
        if not value:
            missing.append(key)
            continue
        paths[key] = path_utils.ensure_absolute(Path(value), REPO_ROOT)
    if missing:
        raise ValueError(f"promotion packet missing required fields: {missing} ({packet_path})")
    for key in OPTIONAL_FIELDS:
        value = packet.get(key)
        if value:
            paths[key] = path_utils.ensure_absolute(Path(value), REPO_ROOT)
    run_manifest = _load_json(paths["run_manifest"])
    return PromotionPacket(packet_path=packet_path, packet=packet, paths=paths, run_manifest=run_manifest)


def load_packets(packet_paths: Iterable[Path], *, allow_missing: bool = True) -> List[PromotionPacket]:
    packets: List[PromotionPacket] = []
    for path in packet_paths:
        path = path_utils.ensure_absolute(path, REPO_ROOT)
        if not path.exists():
            if allow_missing:
                continue
            raise FileNotFoundError(f"missing promotion packet: {path}")
        packets.append(load_packet(path))
    if not packets:
        raise FileNotFoundError("no promotion packets found")
    return packets


def require_clean_manifest(packet: PromotionPacket, label: str) -> None:
    promotability = (packet.packet.get("promotability") or {}) if isinstance(packet.packet, dict) else {}
    promotable = promotability.get("promotable_decision_stage")
    if promotable is False:
        reasons = promotability.get("reasons") or []
        raise RuntimeError(f"{label} promotion packet is not promotable: {reasons}")
    channel = packet.run_manifest.get("channel")
    if channel != "launchd_clean":
        raise RuntimeError(f"{label} run manifest is not clean: channel={channel!r}")


def merge_expected_matrices(packets: Iterable[PromotionPacket]) -> Tuple[Dict[str, Any], str]:
    merged: Dict[str, Any] = {"world_id": None, "profiles": {}}
    world_id: Optional[str] = None
    for packet in packets:
        expected_doc = _load_json(packet.paths["expected_matrix"])
        packet_world = expected_doc.get("world_id") or packet.run_manifest.get("world_id")
        if packet_world:
            if not world_id:
                world_id = packet_world
            elif world_id != packet_world:
                raise ValueError(f"world_id mismatch across promotion packets: {world_id} vs {packet_world}")
        for profile_id, profile in (expected_doc.get("profiles") or {}).items():
            if profile_id in merged["profiles"] and merged["profiles"][profile_id] != profile:
                raise ValueError(f"duplicate profile_id with conflicting entries: {profile_id}")
            merged["profiles"][profile_id] = profile
    merged["world_id"] = world_id or models.WORLD_ID
    return merged, merged["world_id"]


def load_observations(packet: PromotionPacket) -> List[models.RuntimeObservation]:
    rows = _load_json(packet.paths["runtime_events"])
    observations: List[models.RuntimeObservation] = []
    if not isinstance(rows, list):
        raise ValueError(f"runtime_events is not a list: {packet.paths['runtime_events']}")
    for row in rows:
        if not isinstance(row, dict):
            continue
        row = _rewrite_legacy_paths(row)
        try:
            observations.append(models.RuntimeObservation(**row))
        except TypeError as exc:
            raise ValueError(f"invalid runtime_events row in {packet.paths['runtime_events']}: {exc}") from exc
    return observations


def select_impact_map(packets: Iterable[PromotionPacket]) -> Optional[Path]:
    candidates = [p.paths.get("impact_map") for p in packets if p.paths.get("impact_map")]
    if not candidates:
        return None
    unique = {path_utils.to_repo_relative(path, REPO_ROOT) for path in candidates if path}
    if len(unique) > 1:
        raise ValueError(f"multiple impact_map paths found: {sorted(unique)}")
    return candidates[0]
