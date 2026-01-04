#!/usr/bin/env python3
"""
Promote probe-op-structure anchor hits into syncretic policygraph/anchor.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict

REPO_ROOT = Path(__file__).resolve()
for parent in REPO_ROOT.parents:
    if (parent / "book").is_dir():
        REPO_ROOT = parent
        break
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api import path_utils, tooling

REPO_ROOT = path_utils.find_repo_root(Path(__file__).resolve())

WORLD_ID = "sonoma-14.4.1-23E224-arm64-dyld-a3a840f9"
RECEIPT_SCHEMA_VERSION = "policygraph_anchor.promotion_receipt.v1"

DEFAULT_ANCHOR_HITS = (
    REPO_ROOT
    / "book"
    / "evidence"
    / "experiments"
    / "field2-final-final"
    / "probe-op-structure"
    / "out"
    / "anchor_hits.json"
)
DEFAULT_ANCHOR_HITS_RECEIPT = (
    REPO_ROOT
    / "book"
    / "evidence"
    / "experiments"
    / "field2-final-final"
    / "probe-op-structure"
    / "out"
    / "anchor_hits_receipt.json"
)
DEFAULT_ANCHOR_HITS_DELTA = (
    REPO_ROOT
    / "book"
    / "evidence"
    / "experiments"
    / "field2-final-final"
    / "probe-op-structure"
    / "out"
    / "anchor_hits_delta.json"
)
DEFAULT_ANCHOR_HITS_DELTA_RECEIPT = (
    REPO_ROOT
    / "book"
    / "evidence"
    / "experiments"
    / "field2-final-final"
    / "probe-op-structure"
    / "out"
    / "anchor_hits_delta_receipt.json"
)
DEFAULT_OUT = REPO_ROOT / "book" / "evidence" / "syncretic" / "policygraph" / "anchor"


def _rel(path: Path) -> str:
    return path_utils.to_repo_relative(path, repo_root=REPO_ROOT)


def _copy(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(src.read_bytes())


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--anchor-hits", type=Path, default=DEFAULT_ANCHOR_HITS)
    parser.add_argument("--anchor-hits-receipt", type=Path, default=DEFAULT_ANCHOR_HITS_RECEIPT)
    parser.add_argument("--anchor-hits-delta", type=Path, default=DEFAULT_ANCHOR_HITS_DELTA)
    parser.add_argument("--anchor-hits-delta-receipt", type=Path, default=DEFAULT_ANCHOR_HITS_DELTA_RECEIPT)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = _parse_args(argv)
    repo_root = path_utils.find_repo_root(Path(__file__).resolve())
    anchor_hits = path_utils.ensure_absolute(args.anchor_hits, repo_root=repo_root)
    anchor_hits_receipt = path_utils.ensure_absolute(args.anchor_hits_receipt, repo_root=repo_root)
    anchor_hits_delta = path_utils.ensure_absolute(args.anchor_hits_delta, repo_root=repo_root)
    anchor_hits_delta_receipt = path_utils.ensure_absolute(
        args.anchor_hits_delta_receipt, repo_root=repo_root
    )
    out_root = path_utils.ensure_absolute(args.out, repo_root=repo_root)

    for path in [
        anchor_hits,
        anchor_hits_receipt,
        anchor_hits_delta,
        anchor_hits_delta_receipt,
    ]:
        if not path.exists():
            raise FileNotFoundError(f"missing required input: {path}")

    out_anchor_hits = out_root / "anchor_hits.json"
    out_anchor_hits_receipt = out_root / "anchor_hits_receipt.json"
    out_anchor_hits_delta = out_root / "anchor_hits_delta.json"
    out_anchor_hits_delta_receipt = out_root / "anchor_hits_delta_receipt.json"
    promotion_receipt = out_root / "policygraph_anchor_receipt.json"

    _copy(anchor_hits, out_anchor_hits)
    _copy(anchor_hits_receipt, out_anchor_hits_receipt)
    _copy(anchor_hits_delta, out_anchor_hits_delta)
    _copy(anchor_hits_delta_receipt, out_anchor_hits_delta_receipt)

    receipt_inputs: Dict[str, Dict[str, str]] = {
        "anchor_hits": {"path": _rel(anchor_hits), "sha256": tooling.sha256_path(anchor_hits)},
        "anchor_hits_receipt": {
            "path": _rel(anchor_hits_receipt),
            "sha256": tooling.sha256_path(anchor_hits_receipt),
        },
        "anchor_hits_delta": {
            "path": _rel(anchor_hits_delta),
            "sha256": tooling.sha256_path(anchor_hits_delta),
        },
        "anchor_hits_delta_receipt": {
            "path": _rel(anchor_hits_delta_receipt),
            "sha256": tooling.sha256_path(anchor_hits_delta_receipt),
        },
    }
    receipt_outputs: Dict[str, Dict[str, str]] = {
        "anchor_hits": {"path": _rel(out_anchor_hits), "sha256": tooling.sha256_path(out_anchor_hits)},
        "anchor_hits_receipt": {
            "path": _rel(out_anchor_hits_receipt),
            "sha256": tooling.sha256_path(out_anchor_hits_receipt),
        },
        "anchor_hits_delta": {
            "path": _rel(out_anchor_hits_delta),
            "sha256": tooling.sha256_path(out_anchor_hits_delta),
        },
        "anchor_hits_delta_receipt": {
            "path": _rel(out_anchor_hits_delta_receipt),
            "sha256": tooling.sha256_path(out_anchor_hits_delta_receipt),
        },
        "promotion_receipt": {"path": _rel(promotion_receipt), "sha256": None},
    }

    promotion_payload = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "tool": "policygraph_anchor_promotion",
        "world_id": WORLD_ID,
        "inputs": receipt_inputs,
        "outputs": receipt_outputs,
        "command": path_utils.relativize_command(sys.argv, repo_root=repo_root),
    }
    promotion_receipt.parent.mkdir(parents=True, exist_ok=True)
    promotion_receipt.write_text(
        json.dumps(promotion_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print(f"[+] wrote {_rel(out_anchor_hits)}")
    print(f"[+] wrote {_rel(out_anchor_hits_delta)}")
    print(f"[+] wrote {_rel(promotion_receipt)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
