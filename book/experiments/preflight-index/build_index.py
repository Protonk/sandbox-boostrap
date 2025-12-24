#!/usr/bin/env python3
"""
Legacy wrapper for the preflight index builder.

Canonical tool: book/tools/preflight/build_index.py
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional, Sequence


REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.tools.preflight import build_index as tool  # type: ignore


def main(argv: Optional[Sequence[str]] = None) -> int:
    return tool.main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
