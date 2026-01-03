#!/usr/bin/env python3
"""Generate the CARTON inventory graph."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from book.api import path_utils
from book.integration.carton.inventory import graph as graph_mod


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Generate the CARTON inventory graph.")
    parser.add_argument(
        "--out",
        default=str(graph_mod.DEFAULT_OUT_PATH),
        help="repo-relative output path for the inventory graph",
    )
    parser.add_argument(
        "--include-experiments",
        action="store_true",
        help="scan experiments for additional evidence (default: only include referenced inputs)",
    )
    args = parser.parse_args(argv)

    repo_root = path_utils.find_repo_root(Path(__file__))
    out_path = path_utils.ensure_absolute(args.out, repo_root=repo_root)
    doc = graph_mod.build_inventory_graph(repo_root, include_experiments=args.include_experiments)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(doc, indent=2, sort_keys=True))
    rel = path_utils.to_repo_relative(out_path, repo_root=repo_root)
    print(f"[+] wrote {rel}")


if __name__ == "__main__":
    main()
