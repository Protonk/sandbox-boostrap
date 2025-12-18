#!/usr/bin/env python3
"""
HISTORICAL EXAMPLE (legacy decision-tree profiles)

Shim to book/examples/regex_tools/extract_legacy.py.

This tool extracts AppleMatch regex blobs from the legacy decision-tree profile format and is kept for historical
inspection. It is not a modern graph-based profile extractor for this host baseline.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.examples.regex_tools.extract_legacy import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
