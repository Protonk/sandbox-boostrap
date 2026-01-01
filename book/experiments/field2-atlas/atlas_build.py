"""
Synthesize the Field2 Atlas by merging static joins and packet-derived runtime results.

Inputs:
- out/static/field2_records.jsonl (from atlas_static.py)
- promotion_packet.json (runtime-adversarial bundle export surface)

Outputs (derived):
- out/derived/<run_id>/runtime/field2_runtime_results.json
- out/derived/<run_id>/atlas/field2_atlas.json
- out/derived/<run_id>/atlas/summary.json
- out/derived/<run_id>/atlas/summary.md
- out/derived/<run_id>/consumption_receipt.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Ensure repository root is on sys.path for `book` imports when run directly.
REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api import path_utils
from book.api.runtime.analysis import packet_utils

import atlas_runtime


REPO_ROOT = path_utils.find_repo_root(Path(__file__).resolve())
STATIC_PATH = Path(__file__).with_name("out") / "static" / "field2_records.jsonl"
SEEDS_PATH = Path(__file__).with_name("field2_seeds.json")
DEFAULT_OUT_ROOT = Path(__file__).with_name("out") / "derived"
ATLAS_SCHEMA_VERSION = "field2-atlas.atlas.v0"
SUMMARY_SCHEMA_VERSION = "field2-atlas.summary.v0"


def _sha256(path: Path) -> str:
    import hashlib

    data = path.read_bytes()
    return hashlib.sha256(data).hexdigest()


def _load_static_records(path: Path) -> Dict[int, Dict[str, Any]]:
    records: Dict[int, Dict[str, Any]] = {}
    if not path.exists():
        return records
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            record = json.loads(line)
            records[int(record["field2"])] = record
    return records


def _index_runtime_results(runtime_doc: Dict[str, Any]) -> Dict[int, Dict[str, Any]]:
    out: Dict[int, Dict[str, Any]] = {}
    for entry in runtime_doc.get("results", []):
        out[int(entry["field2"])] = entry
    return out


def _derive_status(static_entry: Dict[str, Any] | None, runtime_entry: Dict[str, Any] | None) -> str:
    if runtime_entry:
        status = runtime_entry.get("status")
        if status in {
            "runtime_backed",
            "runtime_backed_historical",
            "runtime_attempted_blocked",
            "missing_probe",
            "missing_actual",
            "no_runtime_candidate",
        }:
            return status
    if static_entry:
        return "static_only"
    return "unknown"


def derive_output_paths(out_root: Path, run_id: str) -> Dict[str, Path]:
    derived_root = atlas_runtime.derived_run_dir(out_root, run_id)
    return {
        "derived_root": derived_root,
        "runtime_results": atlas_runtime.runtime_results_path(out_root, run_id),
        "atlas": derived_root / "atlas" / "field2_atlas.json",
        "summary": derived_root / "atlas" / "summary.json",
        "summary_md": derived_root / "atlas" / "summary.md",
        "receipt": derived_root / "consumption_receipt.json",
    }


def build_atlas(
    runtime_doc: Dict[str, Any],
    *,
    runtime_results_path: Path,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    seeds_doc = json.loads(SEEDS_PATH.read_text())
    seed_ids = {entry["field2"] for entry in seeds_doc.get("seeds", [])}
    static_records = _load_static_records(STATIC_PATH)
    runtime_results = _index_runtime_results(runtime_doc)
    field2_ids = sorted(set(static_records.keys()) | set(runtime_results.keys()))

    if seed_ids != set(field2_ids):
        missing = seed_ids - set(field2_ids)
        extra = set(field2_ids) - seed_ids
        raise ValueError(f"atlas/seed mismatch: missing={sorted(missing)} extra={sorted(extra)}")

    atlas_entries: List[Dict[str, Any]] = []
    for fid in field2_ids:
        static_entry = static_records.get(fid)
        runtime_entry = runtime_results.get(fid)
        atlas_entries.append(
            {
                "field2": fid,
                "filter_name": static_entry.get("filter_name") if static_entry else runtime_entry.get("filter_name"),
                "target_ops": (static_entry or runtime_entry or {}).get("target_ops", []),
                "static": static_entry,
                "runtime": runtime_entry,
                "status": _derive_status(static_entry, runtime_entry),
            }
        )

    summary = {"total": len(atlas_entries), "by_status": {}}
    for entry in atlas_entries:
        status = entry["status"]
        summary["by_status"][status] = summary["by_status"].get(status, 0) + 1

    inputs_meta = {
        "seeds": {
            "path": path_utils.to_repo_relative(SEEDS_PATH, repo_root=REPO_ROOT),
            "sha256": _sha256(SEEDS_PATH),
        },
        "static": {
            "path": path_utils.to_repo_relative(STATIC_PATH, repo_root=REPO_ROOT),
            "sha256": _sha256(STATIC_PATH),
        },
        "runtime": {
            "path": path_utils.to_repo_relative(runtime_results_path, repo_root=REPO_ROOT),
            "sha256": _sha256(runtime_results_path),
        },
    }

    provenance = runtime_doc.get("provenance") or {}
    atlas_doc = {
        "schema_version": ATLAS_SCHEMA_VERSION,
        "world_id": seeds_doc.get("world_id"),
        "provenance": provenance,
        "source_artifacts": {
            "seeds": path_utils.to_repo_relative(SEEDS_PATH, repo_root=REPO_ROOT),
            "static": path_utils.to_repo_relative(STATIC_PATH, repo_root=REPO_ROOT),
            "runtime": path_utils.to_repo_relative(runtime_results_path, repo_root=REPO_ROOT),
        },
        "inputs": inputs_meta,
        "atlas": atlas_entries,
    }

    summary_doc = {
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "world_id": seeds_doc.get("world_id"),
        "provenance": provenance,
        "summary": summary,
    }
    return atlas_doc, summary_doc


def _summary_header(provenance: Dict[str, Any]) -> str:
    run_id = provenance.get("run_id") or "unknown"
    digest = provenance.get("artifact_index_sha256") or "unknown"
    packet = provenance.get("packet") or "unknown"
    return f"<!-- upstream_run_id={run_id} artifact_index_sha256={digest} packet={packet} -->"


def write_outputs(
    atlas_doc: Dict[str, Any],
    summary_doc: Dict[str, Any],
    *,
    atlas_path: Path,
    summary_path: Path,
    summary_md_path: Path,
) -> None:
    atlas_path.parent.mkdir(parents=True, exist_ok=True)
    atlas_path.write_text(json.dumps(atlas_doc, indent=2, sort_keys=True), encoding="utf-8")
    summary_path.write_text(json.dumps(summary_doc, indent=2, sort_keys=True), encoding="utf-8")

    lines = [_summary_header(atlas_doc.get("provenance") or {})]
    lines += ["| field2 | status | profiles | anchors | runtime_scenario |", "| --- | --- | --- | --- | --- |"]
    for entry in atlas_doc.get("atlas", []):
        static = entry.get("static") or {}
        runtime = entry.get("runtime") or {}
        profiles = len(static.get("profiles") or [])
        anchors = len(static.get("anchor_hits") or [])
        scenario = None
        if runtime.get("runtime_candidate"):
            scenario = runtime["runtime_candidate"].get("scenario_id")
        lines.append(f"| {entry['field2']} | {entry['status']} | {profiles} | {anchors} | {scenario or ''} |")
    summary_md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Build Field2 Atlas outputs from a promotion packet.")
    parser.add_argument("--packet", type=Path, required=True, help="Path to promotion_packet.json")
    parser.add_argument(
        "--out-root",
        type=Path,
        default=DEFAULT_OUT_ROOT,
        help="Output root for derived artifacts (run_id subdir will be created)",
    )
    args = parser.parse_args()

    ctx = packet_utils.resolve_packet_context(args.packet, required_exports=atlas_runtime.REQUIRED_EXPORTS, repo_root=REPO_ROOT)
    paths = derive_output_paths(args.out_root, ctx.run_id)
    runtime_doc, _ = atlas_runtime.build_runtime_results(
        args.packet, receipt_path=paths["receipt"], packet_context=ctx
    )
    atlas_runtime.write_results(runtime_doc, output_path=paths["runtime_results"])

    atlas_doc, summary_doc = build_atlas(runtime_doc, runtime_results_path=paths["runtime_results"])
    write_outputs(
        atlas_doc,
        summary_doc,
        atlas_path=paths["atlas"],
        summary_path=paths["summary"],
        summary_md_path=paths["summary_md"],
    )

    atlas_runtime.write_consumption_receipt(
        paths["receipt"],
        world_id=runtime_doc.get("world_id"),
        packet_ctx=ctx,
        exports_used=atlas_runtime.REQUIRED_EXPORTS,
        outputs={
            "runtime_results": paths["runtime_results"],
            "atlas": paths["atlas"],
            "summary": paths["summary"],
            "summary_md": paths["summary_md"],
        },
    )


if __name__ == "__main__":
    main()
