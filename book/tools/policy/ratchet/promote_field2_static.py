#!/usr/bin/env python3
"""
Promote core static field2 evidence into syncretic policygraph/node-fields.

Copies the field2 inventory and unknown census from the field2-filters experiment
into a stable, shared location with a receipt.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict

REPO_ROOT = Path(__file__).resolve()
for parent in REPO_ROOT.parents:
    if (parent / "book").is_dir():
        REPO_ROOT = parent
        break
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api import path_utils, tooling

REPO_ROOT = path_utils.find_repo_root(Path(__file__).resolve())

WORLD_ID = "sonoma-14.4.1-23E224-arm64-dyld-2c0602c5"
RECEIPT_SCHEMA_VERSION = "policygraph_node_fields.core_static_receipt.v0"

DEFAULT_INVENTORY = (
    REPO_ROOT
    / "book"
    / "evidence"
    / "experiments"
    / "field2-final-final"
    / "field2-filters"
    / "out"
    / "field2_inventory.json"
)
DEFAULT_UNKNOWN = (
    REPO_ROOT
    / "book"
    / "evidence"
    / "experiments"
    / "field2-final-final"
    / "field2-filters"
    / "out"
    / "unknown_nodes.json"
)
DEFAULT_OUT = REPO_ROOT / "book" / "evidence" / "syncretic" / "policygraph" / "node-fields"


def _rel(path: Path) -> str:
    return path_utils.to_repo_relative(path, repo_root=REPO_ROOT)


def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
        fh.write("\n")


def _write_promoted_json(out_path: Path, payload: Any) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
        fh.write("\n")


def _ensure_inputs(inventory: Path, unknown_nodes: Path) -> None:
    missing = []
    if not inventory.exists():
        missing.append("field2_inventory")
    if not unknown_nodes.exists():
        missing.append("unknown_nodes")
    if missing:
        raise FileNotFoundError(f"missing required inputs: {', '.join(sorted(missing))}")


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument("--unknown-nodes", type=Path, default=DEFAULT_UNKNOWN)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = _parse_args(argv)
    repo_root = path_utils.find_repo_root(Path(__file__).resolve())
    inventory_path = path_utils.ensure_absolute(args.inventory, repo_root=repo_root)
    unknown_path = path_utils.ensure_absolute(args.unknown_nodes, repo_root=repo_root)
    out_root = path_utils.ensure_absolute(args.out, repo_root=repo_root)

    _ensure_inputs(inventory_path, unknown_path)

    inventory_doc = _load_json(inventory_path)
    unknown_doc = _load_json(unknown_path)

    out_inventory = out_root / "field2_inventory.json"
    out_unknown = out_root / "unknown_nodes.json"
    receipt_path = out_root / "policygraph_node_fields_core_static_receipt.json"

    _write_promoted_json(out_inventory, inventory_doc)
    _write_promoted_json(out_unknown, unknown_doc)

    receipt = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "tool": "policygraph_node_fields_core_static",
        "world_id": WORLD_ID,
        "inputs": {
            "field2_inventory": {
                "path": _rel(inventory_path),
                "sha256": tooling.sha256_path(inventory_path),
            },
            "unknown_nodes": {
                "path": _rel(unknown_path),
                "sha256": tooling.sha256_path(unknown_path),
            },
        },
        "outputs": {
            "field2_inventory": _rel(out_inventory),
            "unknown_nodes": _rel(out_unknown),
            "receipt": _rel(receipt_path),
        },
        "command": path_utils.relativize_command(sys.argv, repo_root=repo_root),
    }
    _write_json(receipt_path, receipt)

    print(f"[+] wrote {_rel(out_inventory)}")
    print(f"[+] wrote {_rel(out_unknown)}")
    print(f"[+] wrote {_rel(receipt_path)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
