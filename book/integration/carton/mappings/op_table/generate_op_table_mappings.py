#!/usr/bin/env python3
"""
Regenerate op_table mapping artifacts from experiment outputs (Sonoma baseline).

This generator intentionally treats the experiments as the source of truth and
publishes curated, world-pinned snapshots under `book/integration/carton/bundle/relationships/mappings/op_table/`.

Inputs:
- book/evidence/experiments/profile-pipeline/node-layout/out/summary.json
- book/evidence/experiments/profile-pipeline/op-table-operation/out/{op_table_map.json,op_table_signatures.json}
- book/evidence/experiments/profile-pipeline/op-table-vocab-alignment/out/op_table_vocab_alignment.json
- book/integration/carton/bundle/relationships/mappings/vocab/{ops.json,filters.json}
- book/world/sonoma-14.4.1-23E224-arm64/world.json

Outputs:
- book/integration/carton/bundle/relationships/mappings/op_table/{op_table_operation_summary.json,op_table_map.json,op_table_signatures.json,op_table_vocab_alignment.json}

Notes:
- We exclude profiles whose id contains "runtime" from the promoted op-table
  mapping set; runtime probe variants remain experiment-local artifacts.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parents[5]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api.path_utils import ensure_absolute, find_repo_root, to_repo_relative
from book.api import world as world_mod


def _load_json(path: Path) -> Any:
    if not path.exists():
        raise FileNotFoundError(f"missing required input: {path}")
    return json.loads(path.read_text())


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _sha256_json_rows(rows: Any) -> str | None:
    if not rows:
        return None
    return hashlib.sha256(json.dumps(rows, sort_keys=True).encode("utf-8")).hexdigest()


def _is_promoted_profile_id(profile_id: str) -> bool:
    return "runtime" not in profile_id


def _load_world_id(repo_root: Path) -> str:
    world_doc, resolution = world_mod.load_world(repo_root=repo_root)
    return world_mod.require_world_id(world_doc, world_path=resolution.entry.world_path)


def _vocab_versions(repo_root: Path) -> Dict[str, Any]:
    ops_path = repo_root / "book/integration/carton/bundle/relationships/mappings/vocab/ops.json"
    filters_path = repo_root / "book/integration/carton/bundle/relationships/mappings/vocab/filters.json"
    ops = _load_json(ops_path)
    filters = _load_json(filters_path)

    ops_rows = ops.get("ops") if isinstance(ops, dict) else None
    filters_rows = filters.get("filters") if isinstance(filters, dict) else None
    ops_rows = ops_rows or []
    filters_rows = filters_rows or []

    ops_status = (ops.get("metadata") or {}).get("status") or ops.get("status")
    filters_status = (filters.get("metadata") or {}).get("status") or filters.get("status")
    return {
        "status": "ok" if ops_status == "ok" and filters_status == "ok" else "partial",
        "ops_count": len(ops_rows),
        "filters_count": len(filters_rows),
        "ops_version": _sha256_json_rows(ops_rows),
        "filters_version": _sha256_json_rows(filters_rows),
    }


def _promote_operation_summary(repo_root: Path, world_id: str, vocab_versions: Dict[str, Any]) -> None:
    src = repo_root / "book/evidence/experiments/profile-pipeline/node-layout/out/summary.json"
    out = repo_root / "book/integration/carton/bundle/relationships/mappings/op_table/op_table_operation_summary.json"
    records = _load_json(src)
    payload = {"metadata": {"world_id": world_id, "vocab_versions": vocab_versions}, "records": records}
    _write_json(out, payload)


def _promote_op_table_map(repo_root: Path, world_id: str, vocab_versions: Dict[str, Any]) -> None:
    src = repo_root / "book/evidence/experiments/profile-pipeline/op-table-operation/out/op_table_map.json"
    out = repo_root / "book/integration/carton/bundle/relationships/mappings/op_table/op_table_map.json"
    data = _load_json(src)
    profiles = data.get("profiles") or {}
    promoted_profiles = {
        name: body for name, body in sorted(profiles.items()) if _is_promoted_profile_id(name)
    }
    payload = {
        "metadata": {"world_id": world_id, "vocab_versions": vocab_versions},
        "single_op_entries": data.get("single_op_entries") or {},
        "profiles": promoted_profiles,
    }
    _write_json(out, payload)


def _promote_op_table_signatures(repo_root: Path, world_id: str, vocab_versions: Dict[str, Any]) -> None:
    src = repo_root / "book/evidence/experiments/profile-pipeline/op-table-operation/out/op_table_signatures.json"
    out = repo_root / "book/integration/carton/bundle/relationships/mappings/op_table/op_table_signatures.json"
    records = _load_json(src)
    records = [r for r in records if _is_promoted_profile_id(str(r.get("name", "")))]
    payload = {"metadata": {"world_id": world_id, "vocab_versions": vocab_versions}, "records": records}
    _write_json(out, payload)


def _promote_op_table_vocab_alignment(repo_root: Path, world_id: str, vocab_versions: Dict[str, Any]) -> None:
    src = repo_root / "book/evidence/experiments/profile-pipeline/op-table-vocab-alignment/out/op_table_vocab_alignment.json"
    out = repo_root / "book/integration/carton/bundle/relationships/mappings/op_table/op_table_vocab_alignment.json"
    data = _load_json(src)
    records = data.get("records") or []
    records = [r for r in records if _is_promoted_profile_id(str(r.get("profile", "")))]
    source_summary = data.get("source_summary")
    if source_summary:
        source_summary = to_repo_relative(ensure_absolute(source_summary, repo_root), repo_root)
    payload = {
        "metadata": {
            "world_id": world_id,
            "vocab_versions": vocab_versions,
            "status": "ok" if data.get("vocab_present") else "partial",
            "vocab_present": bool(data.get("vocab_present")),
            "filter_vocab_present": bool(data.get("filter_vocab_present")),
            "source_summary": source_summary,
        },
        "records": records,
    }
    _write_json(out, payload)


def _write_metadata(repo_root: Path, world_id: str, vocab_versions: Dict[str, Any]) -> None:
    out = repo_root / "book/integration/carton/bundle/relationships/mappings/op_table/metadata.json"
    payload = {
        "artifacts": {
            "op_table_map": "op_table_map.json",
            "op_table_operation_summary": "op_table_operation_summary.json",
            "op_table_signatures": "op_table_signatures.json",
            "op_table_vocab_alignment": "op_table_vocab_alignment.json",
        },
        "notes": (
            "Metadata for op-table mapping artifacts on Sonoma 14.4.1 (23E224); "
            "vocab stamps match book/integration/carton/mappings/vocab."
        ),
        "vocab": vocab_versions,
        "metadata": {"world_id": world_id},
    }
    _write_json(out, payload)


def main() -> None:
    repo_root = find_repo_root(Path(__file__))
    world_id = _load_world_id(repo_root)
    vocab_versions = _vocab_versions(repo_root)

    _promote_operation_summary(repo_root, world_id, vocab_versions)
    _promote_op_table_map(repo_root, world_id, vocab_versions)
    _promote_op_table_signatures(repo_root, world_id, vocab_versions)
    _promote_op_table_vocab_alignment(repo_root, world_id, vocab_versions)
    _write_metadata(repo_root, world_id, vocab_versions)

    out_dir = repo_root / "book/integration/carton/bundle/relationships/mappings/op_table"
    rel = lambda p: to_repo_relative(p, repo_root)
    print(f"[+] wrote {rel(out_dir / 'op_table_operation_summary.json')}")
    print(f"[+] wrote {rel(out_dir / 'op_table_map.json')}")
    print(f"[+] wrote {rel(out_dir / 'op_table_signatures.json')}")
    print(f"[+] wrote {rel(out_dir / 'op_table_vocab_alignment.json')}")
    print(f"[+] wrote {rel(out_dir / 'metadata.json')}")


if __name__ == "__main__":
    main()
