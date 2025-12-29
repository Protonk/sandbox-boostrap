"""
Op-level runtime summary helpers.

Builds per-operation summaries from normalized runtime observations without
relying on experiment-local scripts.

Runtime observations are per-scenario; summaries collapse them by
operation so we can reason about coverage and consistency across probes.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from book.api import path_utils
from book.api.runtime.execution import service as runtime_api
from book.api.runtime.bundles import reader as artifact_reader
from book.api.runtime.contracts import models
from book.api.runtime.analysis.mapping import build as mapping_build


REPO_ROOT = path_utils.find_repo_root(Path(__file__))


def _sha256_path(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        # Chunked reads avoid pulling large bundles into memory.
        for chunk in iter(lambda: fh.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"missing input: {path}")
    return json.loads(path.read_text())


def _load_observations(events_path: Path) -> List[models.RuntimeObservation]:
    rows = _load_json(events_path)
    if not isinstance(rows, list):
        raise ValueError(f"runtime_events is not a list: {events_path}")
    observations: List[models.RuntimeObservation] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        try:
            observations.append(models.RuntimeObservation(**row))
        except TypeError as exc:
            raise ValueError(f"invalid runtime_events row in {events_path}: {exc}") from exc
    return observations


def build_op_runtime_summary(
    observations: Iterable[models.RuntimeObservation],
    *,
    world_id: Optional[str] = None,
    inputs: Optional[List[str]] = None,
    input_hashes: Optional[Dict[str, str]] = None,
    source_jobs: Optional[List[str]] = None,
    notes: Optional[str] = None,
) -> Dict[str, Any]:
    """Build an op-level summary document from runtime observations."""
    summary = mapping_build.build_ops(observations, world_id=world_id)
    meta = summary.get("meta") or {}
    if inputs is not None:
        meta["inputs"] = inputs
    if input_hashes is not None:
        meta["input_hashes"] = input_hashes
    if source_jobs is not None:
        meta["source_jobs"] = source_jobs
    if notes is not None:
        meta["notes"] = notes
    summary["meta"] = meta
    return summary


def write_op_runtime_summary(summary: Dict[str, Any], out_path: Path) -> Path:
    """Write an op-level summary document to disk."""
    out_path = path_utils.ensure_absolute(out_path, REPO_ROOT)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(summary, indent=2))
    return out_path


def summarize_ops_from_bundle(
    bundle_root: Path,
    *,
    out_path: Optional[Path] = None,
    strict: bool = True,
) -> Dict[str, Any]:
    """Summarize ops for a committed bundle; optionally write to disk."""
    bundle_dir, _ = artifact_reader.resolve_bundle_dir(bundle_root, repo_root=REPO_ROOT)
    bundle_dir = path_utils.ensure_absolute(bundle_dir, REPO_ROOT)
    if strict:
        runtime_api.load_bundle(bundle_dir)

    events_path = bundle_dir / "runtime_events.normalized.json"
    manifest_path = bundle_dir / "run_manifest.json"
    run_manifest = _load_json(manifest_path) if manifest_path.exists() else {}
    world_id = run_manifest.get("world_id") or models.WORLD_ID

    observations = _load_observations(events_path)
    inputs = [
        path_utils.to_repo_relative(events_path, repo_root=REPO_ROOT),
        path_utils.to_repo_relative(manifest_path, repo_root=REPO_ROOT) if manifest_path.exists() else None,
    ]
    inputs = [p for p in inputs if p]
    input_hashes = {path_utils.to_repo_relative(events_path, repo_root=REPO_ROOT): _sha256_path(events_path)}
    if manifest_path.exists():
        input_hashes[path_utils.to_repo_relative(manifest_path, repo_root=REPO_ROOT)] = _sha256_path(manifest_path)

    summary = build_op_runtime_summary(
        observations,
        world_id=world_id,
        inputs=inputs,
        input_hashes=input_hashes,
        source_jobs=["runtime_bundle"],
        notes="Op-level summary derived from a runtime bundle (decision-stage only when promotable).",
    )
    if out_path is not None:
        write_op_runtime_summary(summary, out_path)
    return summary


def _load_promotion_packet(packet_path: Path) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    packet = _load_json(packet_path)
    run_manifest_path = packet.get("run_manifest")
    if not run_manifest_path:
        raise ValueError(f"promotion packet missing run_manifest: {packet_path}")
    run_manifest = _load_json(path_utils.ensure_absolute(Path(run_manifest_path), REPO_ROOT))
    return packet, run_manifest


def _require_promotable(packet: Dict[str, Any], run_manifest: Dict[str, Any], *, label: str) -> None:
    promotability = packet.get("promotability") or {}
    promotable = promotability.get("promotable_decision_stage")
    if promotable is False:
        reasons = promotability.get("reasons") or []
        raise RuntimeError(f"{label} promotion packet is not promotable: {reasons}")
    channel = run_manifest.get("channel")
    if channel != "launchd_clean":
        raise RuntimeError(f"{label} run manifest is not clean: channel={channel!r}")


def summarize_ops_from_packet(
    packet_path: Path,
    *,
    out_path: Optional[Path] = None,
    require_promotable: bool = True,
) -> Dict[str, Any]:
    """Summarize ops from a promotion packet; optionally enforce promotability."""
    packet_path = path_utils.ensure_absolute(packet_path, REPO_ROOT)
    packet, run_manifest = _load_promotion_packet(packet_path)
    if require_promotable:
        _require_promotable(packet, run_manifest, label=str(packet_path))

    runtime_events_path = packet.get("runtime_events")
    if not runtime_events_path:
        raise ValueError(f"promotion packet missing runtime_events: {packet_path}")
    events_path = path_utils.ensure_absolute(Path(runtime_events_path), REPO_ROOT)
    observations = _load_observations(events_path)
    world_id = run_manifest.get("world_id") or models.WORLD_ID

    inputs = [
        path_utils.to_repo_relative(packet_path, repo_root=REPO_ROOT),
        path_utils.to_repo_relative(events_path, repo_root=REPO_ROOT),
    ]
    input_hashes = {
        path_utils.to_repo_relative(packet_path, repo_root=REPO_ROOT): _sha256_path(packet_path),
        path_utils.to_repo_relative(events_path, repo_root=REPO_ROOT): _sha256_path(events_path),
    }
    summary = build_op_runtime_summary(
        observations,
        world_id=world_id,
        inputs=inputs,
        input_hashes=input_hashes,
        source_jobs=["promotion_packet"],
        notes="Op-level summary derived from a promotion packet (decision-stage only when promotable).",
    )
    if out_path is not None:
        write_op_runtime_summary(summary, out_path)
    return summary
