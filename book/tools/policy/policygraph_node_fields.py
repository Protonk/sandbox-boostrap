#!/usr/bin/env python3
"""
PolicyGraph node field enumerator (skeleton).

This tool will become the source of truth for fixed-width PolicyGraph node
fields on the Sonoma baseline. It is intentionally deterministic: default mode
reads pinned artifacts only, and runtime evidence is packet-driven.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api import path_utils  # type: ignore


WORLD_ID = "sonoma-14.4.1-23E224-arm64-dyld-2c0602c5"
SCHEMA_VERSION = 0


def _rel(path: Path) -> str:
    return path_utils.to_repo_relative(path, repo_root=REPO_ROOT)


def _static_inputs() -> Dict[str, Path]:
    return {
        "tag_layouts": REPO_ROOT
        / "book/integration/carton/bundle/relationships/mappings/tag_layouts/tag_layouts.json",
        "vocab_ops": REPO_ROOT / "book/integration/carton/bundle/relationships/mappings/vocab/ops.json",
        "vocab_filters": REPO_ROOT / "book/integration/carton/bundle/relationships/mappings/vocab/filters.json",
        "anchor_filter_map": REPO_ROOT
        / "book/integration/carton/bundle/relationships/mappings/anchors/anchor_filter_map.json",
        "field2_inventory": REPO_ROOT
        / "book/evidence/experiments/field2-final-final/field2-filters/out/field2_inventory.json",
        "anchor_hits": REPO_ROOT
        / "book/evidence/experiments/field2-final-final/probe-op-structure/out/anchor_hits.json",
        "anchor_hits_delta": REPO_ROOT
        / "book/evidence/experiments/field2-final-final/probe-op-structure/out/anchor_hits_delta.json",
        "field2_seeds": REPO_ROOT / "book/evidence/experiments/field2-final-final/field2-atlas/field2_seeds.json",
        "network_matrix_root": REPO_ROOT
        / "book/evidence/experiments/field2-final-final/libsandbox-encoder/out/network_matrix",
    }


def _output_paths(out_root: Path) -> Dict[str, Path]:
    return {
        "fields": out_root / "policygraph_node_fields.json",
        "arg16": out_root / "policygraph_node_arg16.json",
        "unknowns": out_root / "policygraph_node_unknowns.json",
        "receipt": out_root / "policygraph_node_fields_receipt.json",
    }


def _describe(args: argparse.Namespace) -> int:
    out_root = Path(args.out).resolve()
    inputs = _static_inputs()
    outputs = _output_paths(out_root)
    doc = {
        "schema_version": SCHEMA_VERSION,
        "tool": "policygraph_node_fields",
        "world_id": WORLD_ID,
        "mode": "describe",
        "inputs": {name: {"path": _rel(path), "required": True} for name, path in inputs.items()},
        "optional": {
            "promotion_packet": _rel(Path(args.packet)) if args.packet else None,
            "validator_bin": _rel(Path(args.validator)) if args.validator else None,
        },
        "outputs": {name: _rel(path) for name, path in outputs.items()},
    }
    print(json.dumps(doc, indent=2, sort_keys=True))
    return 0


def _build(_: argparse.Namespace) -> int:
    raise SystemExit("policygraph_node_fields: build not implemented (use --describe)")


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="policygraph_node_fields",
        description="Enumerate fixed-width PolicyGraph node fields (skeleton).",
    )
    parser.add_argument("--out", default=str(Path(__file__).resolve().parent / "out"))
    parser.add_argument("--packet", help="Promotion packet path (optional).")
    parser.add_argument("--validator", help="sb_validator binary path (optional).")
    parser.add_argument("--describe", action="store_true", help="Print intended inputs/outputs and exit.")

    args = parser.parse_args(argv)
    return args


def main(argv: list[str]) -> int:
    args = _parse_args(argv)
    if args.describe:
        return _describe(args)
    return _build(args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
