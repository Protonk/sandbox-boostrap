"""
Legacy wrapper for the golden corpus builder.

Canonical tool: book/graph/concepts/validation/golden_corpus_build.py
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional, Sequence


REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.graph.concepts.validation import golden_corpus_build as tool  # type: ignore


def main(argv: Optional[Sequence[str]] = None) -> int:
    return tool.main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
