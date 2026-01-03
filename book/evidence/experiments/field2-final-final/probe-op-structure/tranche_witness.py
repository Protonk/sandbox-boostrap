#!/usr/bin/env python3
"""
Emit a tranche-scoped structural witness for the selected `field2` value.

This is intended to turn `book/evidence/experiments/field2-final-final/out/tranche.json`
into a small, checkable artifact under this experiment:

- Locate all profiles in `field2_inventory.json` that contain the selected field2.
- Resolve the compiled profile blob path for each profile id.
- Decode nodes and record the exact nodes whose third u16 payload slot matches the tranche.

Output:
- book/evidence/experiments/field2-final-final/probe-op-structure/out/tranche_witness.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve()
for parent in REPO_ROOT.parents:
    if (parent / "book").is_dir():
        REPO_ROOT = parent
        break
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api import path_utils  # type: ignore
from book.api.profile import decoder  # type: ignore
from book.api.profile import digests as digests_mod  # type: ignore

SCHEMA_VERSION = "field2-tranche-witness.v0"

DEFAULT_TRANCHE = REPO_ROOT / "book/evidence/experiments/field2-final-final/out/tranche.json"
DEFAULT_INVENTORY = REPO_ROOT / "book/evidence/experiments/field2-final-final/field2-filters/out/field2_inventory.json"
DEFAULT_OUT = REPO_ROOT / "book/evidence/experiments/field2-final-final/probe-op-structure/out/tranche_witness.json"


def load_json(path: Path) -> Any:
    return json.loads(path.read_text())


def _resolve_profile_blob(profile_id: str) -> Optional[Path]:
    if profile_id.startswith("sys:"):
        name = profile_id.split(":", 1)[1]
        canonical = digests_mod.canonical_system_profile_blobs(REPO_ROOT)
        return canonical.get(name)

    if profile_id.startswith("probe-op:"):
        stem = profile_id.split(":", 1)[1]
        return (
            REPO_ROOT
            / "book/evidence/experiments/field2-final-final/probe-op-structure/sb/build"
            / f"{stem}.bin"
        )

    if profile_id.startswith("probe:"):
        stem = profile_id.split(":", 1)[1]
        return (
            REPO_ROOT
            / "book/evidence/experiments/field2-final-final/field2-filters/sb/build"
            / f"{stem}.bin"
        )

    return None


def _inventory_hits(field2_inventory: Dict[str, Any], *, field2: int) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    for profile_id, rec in field2_inventory.items():
        for entry in rec.get("field2", []) or []:
            if entry.get("raw") != field2:
                continue
            hits.append(
                {
                    "profile": profile_id,
                    "raw": entry.get("raw"),
                    "raw_hex": entry.get("raw_hex"),
                    "hi": entry.get("hi"),
                    "lo": entry.get("lo"),
                    "name": entry.get("name"),
                    "count": entry.get("count"),
                    "tags": entry.get("tags") or {},
                }
            )
    hits.sort(key=lambda h: (h.get("count") or 0, h.get("profile") or ""), reverse=True)
    return hits


def _node_hits(nodes: List[Dict[str, Any]], *, field2: int) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for idx, node in enumerate(nodes):
        fields = node.get("fields") or []
        if not (isinstance(fields, list) and len(fields) > 2 and fields[2] == field2):
            continue
        out.append(
            {
                "idx": idx,
                "offset": node.get("offset"),
                "tag": node.get("tag"),
                "u16_role": node.get("u16_role"),
                "record_size": node.get("record_size"),
                "fields": fields,
                "filter_arg_raw": node.get("filter_arg_raw"),
                "filter_vocab_ref": node.get("filter_vocab_ref"),
                "filter_out_of_vocab": node.get("filter_out_of_vocab"),
                "layout_provenance": node.get("layout_provenance"),
                "literal_refs": node.get("literal_refs") or [],
                "literal_refs_provenance": node.get("literal_refs_provenance"),
                "hex": node.get("hex"),
            }
        )
    return out


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--tranche", type=Path, default=DEFAULT_TRANCHE)
    ap.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args(argv)

    repo_root = path_utils.find_repo_root(Path(__file__).resolve())

    tranche = load_json(args.tranche)
    selected = tranche.get("selected") or {}
    field2 = selected.get("field2")
    if not isinstance(field2, int):
        raise SystemExit("tranche.json missing selected.field2 int")

    inventory = load_json(args.inventory)
    hits = _inventory_hits(inventory, field2=field2)

    profiles_out: Dict[str, Any] = {}
    for hit in hits:
        profile_id = hit["profile"]
        blob_path = _resolve_profile_blob(profile_id)
        if not blob_path or not blob_path.exists():
            profiles_out[profile_id] = {
                "blob": None if not blob_path else path_utils.to_repo_relative(blob_path, repo_root=repo_root),
                "error": "missing_blob",
            }
            continue

        try:
            decoded = decoder.decode_profile_dict(blob_path.read_bytes())
        except Exception as e:
            profiles_out[profile_id] = {
                "blob": path_utils.to_repo_relative(blob_path, repo_root=repo_root),
                "error": f"decode_error:{type(e).__name__}",
            }
            continue

        nodes = decoded.get("nodes") or []
        node_hits = _node_hits(nodes, field2=field2)
        profiles_out[profile_id] = {
            "blob": path_utils.to_repo_relative(blob_path, repo_root=repo_root),
            "op_count": decoded.get("op_count"),
            "node_count": decoded.get("node_count"),
            "literal_strings_count": len(decoded.get("literal_strings") or []),
            "node_hits": node_hits,
        }

    out_doc = {
        "schema_version": SCHEMA_VERSION,
        "world_id": tranche.get("world_id"),
        "inputs": {
            "tranche": path_utils.to_repo_relative(args.tranche, repo_root=repo_root),
            "inventory": path_utils.to_repo_relative(args.inventory, repo_root=repo_root),
        },
        "selected": selected,
        "inventory_hits": hits,
        "profiles": profiles_out,
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(out_doc, indent=2) + "\n")
    print(f"[+] wrote {path_utils.to_repo_relative(args.out, repo_root=repo_root)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

