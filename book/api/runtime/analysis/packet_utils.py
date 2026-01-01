"""
Promotion packet helpers for packet-only consumers.

These utilities validate promotion packets, resolve committed bundles, and
provide provenance metadata for derived outputs.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from book.api import path_utils, tooling
from book.api.runtime.bundles import promotion as promotion_mod
from book.api.runtime.execution import service as runtime_api


REPO_ROOT = path_utils.find_repo_root(Path(__file__))


@dataclass(frozen=True)
class PacketContext:
    packet_path: Path
    packet: Dict[str, Any]
    run_manifest_path: Path
    run_manifest: Dict[str, Any]
    bundle_dir: Path
    bundle_index: Dict[str, Any]
    artifact_index_path: Path
    artifact_index_sha256: str
    run_id: str
    export_paths: Dict[str, Path]


def _load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"missing input: {path}")
    doc = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    if not isinstance(doc, dict):
        raise ValueError(f"expected JSON object at {path}")
    return doc


def load_promotion_packet(packet_path: Path, *, repo_root: Path = REPO_ROOT) -> Dict[str, Any]:
    packet_path = path_utils.ensure_absolute(packet_path, repo_root)
    if packet_path.is_dir():
        raise ValueError(f"expected promotion_packet.json file, got directory: {packet_path}")
    packet = _load_json(packet_path)
    schema_version = packet.get("schema_version")
    if not isinstance(schema_version, str) or not schema_version.startswith("runtime-tools.promotion_packet."):
        expected = promotion_mod.PROMOTION_PACKET_SCHEMA_VERSION
        raise ValueError(f"unexpected promotion packet schema_version (got {schema_version!r}, expected {expected})")
    return packet


def resolve_packet_context(
    packet_path: Path,
    *,
    required_exports: Iterable[str],
    repo_root: Path = REPO_ROOT,
) -> PacketContext:
    packet_path = path_utils.ensure_absolute(packet_path, repo_root)
    packet = load_promotion_packet(packet_path, repo_root=repo_root)

    run_manifest_rel = packet.get("run_manifest")
    if not run_manifest_rel:
        raise ValueError(f"promotion packet missing run_manifest: {packet_path}")
    run_manifest_path = path_utils.ensure_absolute(Path(run_manifest_rel), repo_root)
    run_manifest = _load_json(run_manifest_path)

    bundle_dir = run_manifest_path.parent
    bundle_index = runtime_api.load_bundle(bundle_dir)
    artifact_index_path = bundle_dir / "artifact_index.json"
    if not artifact_index_path.exists():
        raise FileNotFoundError(f"missing artifact_index.json: {artifact_index_path}")
    artifact_index_sha256 = tooling.sha256_path(artifact_index_path)

    run_id = run_manifest.get("run_id") or bundle_index.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        raise ValueError(f"missing run_id in run_manifest: {run_manifest_path}")
    if bundle_index.get("run_id") and run_id != bundle_index.get("run_id"):
        raise ValueError("run_id mismatch between run_manifest and artifact_index")

    export_paths: Dict[str, Path] = {}
    missing: list[str] = []
    for key in required_exports:
        value = packet.get(key)
        if not value:
            missing.append(key)
            continue
        export_path = path_utils.ensure_absolute(Path(value), repo_root)
        if not export_path.exists():
            raise FileNotFoundError(f"promotion packet export missing: {key} -> {export_path}")
        export_paths[key] = export_path

    if missing:
        raise ValueError(f"promotion packet missing exports: {sorted(set(missing))}")

    return PacketContext(
        packet_path=packet_path,
        packet=packet,
        run_manifest_path=run_manifest_path,
        run_manifest=run_manifest,
        bundle_dir=bundle_dir,
        bundle_index=bundle_index,
        artifact_index_path=artifact_index_path,
        artifact_index_sha256=artifact_index_sha256,
        run_id=run_id,
        export_paths=export_paths,
    )


def format_packet_provenance(
    ctx: PacketContext,
    *,
    exports: Iterable[str],
    receipt_path: Optional[Path] = None,
    repo_root: Path = REPO_ROOT,
) -> Dict[str, Any]:
    export_paths: Dict[str, str] = {}
    for key in exports:
        if key not in ctx.export_paths:
            raise KeyError(f"export {key!r} missing from packet context")
        export_paths[key] = path_utils.to_repo_relative(ctx.export_paths[key], repo_root=repo_root)
    return {
        "packet": path_utils.to_repo_relative(ctx.packet_path, repo_root=repo_root),
        "bundle_dir": path_utils.to_repo_relative(ctx.bundle_dir, repo_root=repo_root),
        "run_id": ctx.run_id,
        "artifact_index": path_utils.to_repo_relative(ctx.artifact_index_path, repo_root=repo_root),
        "artifact_index_sha256": ctx.artifact_index_sha256,
        "exports": export_paths,
        "consumption_receipt": path_utils.to_repo_relative(receipt_path, repo_root=repo_root) if receipt_path else None,
    }
