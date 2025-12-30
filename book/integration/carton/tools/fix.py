#!/usr/bin/env python3
"""Run CARTON fixers to generate relationship and view outputs."""

from __future__ import annotations

import argparse
from typing import List, Optional

from book.integration.carton.fixers import registry


def _parse_ids(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="Run CARTON fixers")
    parser.add_argument(
        "--ids",
        help="comma-separated fixer ids to run (default: all)",
    )
    args = parser.parse_args(argv)

    ids = _parse_ids(args.ids)
    registry.run_fixers(ids=ids if ids else None)


if __name__ == "__main__":
    main()
