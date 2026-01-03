#!/usr/bin/env python3
"""
Generate a CARTON mapping pointer for PolicyGraph node field outputs.

This mapping anchors the syncretic policygraph/node-fields outputs into the
CARTON bundle with explicit provenance and a compact summary.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict

REPO_ROOT = Path(__file__).resolve().parents[5]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api import path_utils, tooling  # type: ignore


WORLD_ID = "sonoma-14.4.1-23E224-arm64-dyld-2c0602c5"
SCHEMA_VERSION = "policygraph_node_fields.mapping.v0"

SYN_ROOT = REPO_ROOT / "book/evidence/syncretic/policygraph/node-fields"
FIELDS_PATH = SYN_ROOT / "policygraph_node_fields.json"
ARG16_PATH = SYN_ROOT / "policygraph_node_arg16.json"
UNKNOWNS_PATH = SYN_ROOT / "policygraph_node_unknowns.json"
RECEIPT_PATH = SYN_ROOT / "policygraph_node_fields_receipt.json"
REPORT_PATH = SYN_ROOT / "policygraph_node_fields.md"

OUT_PATH = (
    REPO_ROOT
    / "book/integration/carton/bundle/relationships/mappings/policy/policygraph_node_fields.json"
)


def _rel(path: Path) -> str:
    return path_utils.to_repo_relative(path, repo_root=REPO_ROOT)


def _load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"missing required input: {path}")
    return json.loads(path.read_text())


def _check_world_id(doc: Dict[str, Any], label: str) -> None:
    world_id = doc.get("world_id")
    if not world_id and isinstance(doc.get("metadata"), dict):
        world_id = doc["metadata"].get("world_id")
    if world_id and world_id != WORLD_ID:
        raise ValueError(f"{label} world_id mismatch: {world_id} != {WORLD_ID}")


def main() -> None:
    fields_doc = _load_json(FIELDS_PATH)
    arg16_doc = _load_json(ARG16_PATH)
    unknowns_doc = _load_json(UNKNOWNS_PATH)
    receipt_doc = _load_json(RECEIPT_PATH)

    _check_world_id(fields_doc, "fields")
    _check_world_id(arg16_doc, "arg16")
    _check_world_id(unknowns_doc, "unknowns")

    runtime_annotation = receipt_doc.get("packet")
    status = "ok" if runtime_annotation else "partial"

    runtime_summary = arg16_doc.get("runtime_summary") or {}
    unknowns = unknowns_doc.get("arg16_unknowns") or []

    sources = {
        "fields": {"path": _rel(FIELDS_PATH), "sha256": tooling.sha256_path(FIELDS_PATH)},
        "arg16": {"path": _rel(ARG16_PATH), "sha256": tooling.sha256_path(ARG16_PATH)},
        "unknowns": {"path": _rel(UNKNOWNS_PATH), "sha256": tooling.sha256_path(UNKNOWNS_PATH)},
        "receipt": {"path": _rel(RECEIPT_PATH), "sha256": tooling.sha256_path(RECEIPT_PATH)},
        "report": {"path": _rel(REPORT_PATH), "sha256": tooling.sha256_path(REPORT_PATH)},
    }

    payload: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "metadata": {
            "world_id": WORLD_ID,
            "status": status,
            "inputs": [entry["path"] for entry in sources.values()],
            "source_jobs": ["generator:policygraph_node_fields"],
        },
        "summary": {
            "record_size_bytes": fields_doc.get("record_size_bytes"),
            "field_count": fields_doc.get("field_count"),
            "arg16_field_index": fields_doc.get("arg16_field_index"),
            "arg16_total_values": len(arg16_doc.get("records") or []),
            "arg16_mapped_values": sum(
                1 for rec in (arg16_doc.get("records") or []) if rec.get("filter_name")
            ),
            "arg16_opaque_values": sum(
                1 for rec in (arg16_doc.get("records") or []) if not rec.get("filter_name")
            ),
            "unknown_arg16_values": len(unknowns),
            "runtime_summary": runtime_summary,
        },
        "runtime_annotation": runtime_annotation,
        "sources": sources,
    }

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True))
    print(f"[+] wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
