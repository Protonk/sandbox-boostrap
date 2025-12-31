#!/usr/bin/env python3
"""Derive VFS canonicalization summaries from a committed runtime bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List

from book.api import path_utils
from book.api.profile import decoder
from book.api.runtime.bundles import reader as bundle_reader
from book.api.runtime.plans import builder as runtime_plan_builder
from book.api.runtime.execution import service as runtime_service


REPO_ROOT = path_utils.find_repo_root(Path(__file__))
BASE_DIR = Path(__file__).resolve().parent
OUT_ROOT = BASE_DIR / "out"
DERIVED_ROOT = OUT_ROOT / "derived"
TEMPLATE_ID = "vfs-canonicalization"

RUNTIME_SUMMARY_SCHEMA = "vfs-canonicalization.runtime_summary.v0.1"
DECODE_SCHEMA = "vfs-canonicalization.decode_profiles.v0.1"
MISMATCH_SCHEMA = "vfs-canonicalization.mismatch_summary.v0.1"


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text())


def _bundle_context(bundle_root: Path) -> tuple[Path, dict[str, Any]]:
    runtime_service.load_bundle(bundle_root)
    run_dir, run_id = bundle_reader.resolve_bundle_dir(bundle_root, repo_root=REPO_ROOT)
    run_dir = path_utils.ensure_absolute(run_dir, repo_root=REPO_ROOT)

    manifest_path = run_dir / "run_manifest.json"
    manifest = _load_json(manifest_path)
    artifact_index_path = run_dir / "artifact_index.json"

    bundle_meta = {
        "bundle_dir": path_utils.to_repo_relative(run_dir, repo_root=REPO_ROOT),
        "run_id": run_id or manifest.get("run_id"),
        "artifact_index": path_utils.to_repo_relative(artifact_index_path, repo_root=REPO_ROOT),
        "artifact_index_sha256": _sha256_path(artifact_index_path) if artifact_index_path.exists() else None,
    }
    return run_dir, bundle_meta


def _literal_candidates(value: str) -> set[str]:
    out: set[str] = set()
    if not value:
        return out
    trimmed = value.lstrip()
    if trimmed.startswith("/"):
        out.add(trimmed)
    if trimmed:
        body = trimmed[1:]
        out.add(body)
        if body and not body.startswith("/"):
            out.add(f"/{body}")
    return out


def _anchor_present(anchor: str, literals: set[str]) -> bool:
    if anchor in literals:
        return True
    parts = anchor.strip("/").split("/")
    if not parts:
        return False
    first = f"/{parts[0]}/"
    if first not in literals:
        return False
    if len(parts) == 1:
        return True
    tail = "/".join(parts[1:])
    if tail in literals or f"/{tail}" in literals:
        return True
    if len(parts) >= 3:
        mid = f"{parts[1]}/"
        tail_rest = "/".join(parts[2:])
        if ((mid in literals) or (f"/{parts[1]}/" in literals)) and (
            (tail_rest in literals) or (f"/{tail_rest}" in literals)
        ):
            return True
    if all(((seg in literals) or (f"/{seg}" in literals) or (f"{seg}/" in literals)) for seg in parts[1:]):
        return True
    return False


def _decode_profiles(run_dir: Path, bundle_meta: dict[str, Any]) -> dict[str, Any]:
    template = runtime_plan_builder.load_plan_template(TEMPLATE_ID)
    anchors = runtime_plan_builder.collect_anchor_paths(template)

    matrix_path = run_dir / "expected_matrix.generated.json"
    if not matrix_path.exists():
        matrix_path = run_dir / "expected_matrix.json"
    matrix = _load_json(matrix_path)

    profiles_out: Dict[str, Any] = {}
    for profile_id, rec in (matrix.get("profiles") or {}).items():
        blob_ref = rec.get("blob")
        if not blob_ref:
            continue
        blob_path = path_utils.ensure_absolute(Path(blob_ref), repo_root=REPO_ROOT)
        data = blob_path.read_bytes()
        dec = decoder.decode_profile_dict(data)
        literal_set: set[str] = set()
        for lit in dec.get("literal_strings") or []:
            literal_set.update(_literal_candidates(lit))
        nodes = dec.get("nodes") or []
        anchors_info: List[Dict[str, Any]] = []
        for anchor in anchors:
            present = _anchor_present(anchor, literal_set)
            tag_ids = set()
            field2_vals = set()
            for node in nodes:
                ref_candidates = set()
                for ref in (node.get("literal_refs") or []):
                    ref_candidates.update(_literal_candidates(ref))
                if _anchor_present(anchor, ref_candidates):
                    tag_ids.add(node.get("tag"))
                    fields = node.get("fields") or []
                    if len(fields) > 2:
                        field2_vals.add(fields[2])
            anchors_info.append(
                {
                    "path": anchor,
                    "present": present,
                    "tags": sorted(tag_ids),
                    "field2_values": sorted(field2_vals),
                }
            )
        profiles_out[profile_id] = {
            "anchors": anchors_info,
            "literal_candidates": sorted(literal_set),
            "node_count": dec.get("node_count"),
            "tag_counts": dec.get("tag_counts"),
        }

    return {
        "schema_version": DECODE_SCHEMA,
        "world_id": matrix.get("world_id"),
        "bundle": bundle_meta,
        "profiles": profiles_out,
    }


def _summarize_runtime(run_dir: Path, bundle_meta: dict[str, Any]) -> dict[str, Any]:
    events = _load_json(run_dir / "runtime_events.normalized.json")
    witness_doc = _load_json(run_dir / "path_witnesses.json")

    witness_map: Dict[tuple[str, str, str], Dict[str, Any]] = {}
    for rec in witness_doc.get("records") or []:
        if rec.get("lane") != "scenario":
            continue
        profile_id = rec.get("profile_id")
        op = rec.get("operation")
        requested = rec.get("requested_path")
        if profile_id and op and requested:
            witness_map[(profile_id, op, requested)] = rec

    records: List[Dict[str, Any]] = []
    for event in events:
        record = dict(event)
        profile_id = record.get("profile_id")
        operation = record.get("operation")
        requested_path = record.get("requested_path") or record.get("target")
        witness = None
        if profile_id and operation and requested_path:
            witness = witness_map.get((profile_id, operation, requested_path))

        if witness:
            record["observed_path_nofirmlink"] = witness.get("observed_path_nofirmlink")
            record["observed_path_nofirmlink_source"] = witness.get("observed_path_nofirmlink_source")
            record["observed_path_nofirmlink_errno"] = witness.get("observed_path_nofirmlink_errno")
        else:
            record["observed_path_nofirmlink"] = None
            record["observed_path_nofirmlink_source"] = "missing_witness"
            record["observed_path_nofirmlink_errno"] = None

        records.append(record)

    return {
        "schema_version": RUNTIME_SUMMARY_SCHEMA,
        "world_id": (witness_doc.get("world_id") or (events[0].get("world_id") if events else None)),
        "bundle": bundle_meta,
        "records": records,
    }


def _mismatch_summary(world_id: str, bundle_meta: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": MISMATCH_SCHEMA,
        "world_id": world_id,
        "bundle": bundle_meta,
        "profiles": {
            "vfs_tmp_only": {
                "kind": "canonicalization",
                "note": "Profile mentions only /tmp/* paths; alias and canonical requests are denied across the path set, consistent with canonicalization-before-enforcement with only /private/... literals effective.",
            },
            "vfs_private_tmp_only": {
                "kind": "canonicalization",
                "note": "Profile mentions only canonical /private/... paths; alias and canonical requests are allowed across the path set; literal on canonical path effective for both.",
            },
            "vfs_both_paths": {
                "kind": "control",
                "note": "Profile mentions both alias and canonical forms; all requests allowed; control confirming canonical behavior.",
            },
        },
    }


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Derive vfs-canonicalization summaries from a committed bundle")
    parser.add_argument("--bundle", type=Path, default=OUT_ROOT, help="Bundle root (out/ or run_id dir)")
    parser.add_argument("--out-dir", type=Path, default=DERIVED_ROOT, help="Output directory for derived artifacts")
    args = parser.parse_args()

    bundle_root = path_utils.ensure_absolute(args.bundle, repo_root=REPO_ROOT)
    run_dir, bundle_meta = _bundle_context(bundle_root)

    runtime_summary = _summarize_runtime(run_dir, bundle_meta)
    decode_summary = _decode_profiles(run_dir, bundle_meta)
    mismatch_summary = _mismatch_summary(runtime_summary.get("world_id"), bundle_meta)

    out_dir = path_utils.ensure_absolute(args.out_dir, repo_root=REPO_ROOT)
    _write_json(out_dir / "runtime_results.json", runtime_summary)
    _write_json(out_dir / "decode_tmp_profiles.json", decode_summary)
    _write_json(out_dir / "mismatch_summary.json", mismatch_summary)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
