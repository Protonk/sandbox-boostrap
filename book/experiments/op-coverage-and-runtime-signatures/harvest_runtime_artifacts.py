from __future__ import annotations

import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api import path_utils

ROOT = REPO_ROOT
OUT_DIR = Path(__file__).resolve().parent / "out"
CANONICAL = ROOT / "book" / "graph" / "mappings" / "runtime" / "op_runtime_summary.json"


def main() -> None:
    """
    Deprecated wrapper: copy the canonical op runtime summary into this suite's out/ for convenience.
    """
    if not CANONICAL.exists():
        print(f"Missing canonical summary: {path_utils.to_repo_relative(CANONICAL, repo_root=REPO_ROOT)}")
        print("Regenerate via book/graph/mappings/runtime/promote_from_packets.py.")
        return
    OUT_DIR.mkdir(exist_ok=True)
    dst = OUT_DIR / "op_runtime_summary.json"
    shutil.copy2(CANONICAL, dst)
    print(f"Copied canonical summary to {path_utils.to_repo_relative(dst, repo_root=REPO_ROOT)}")
    print(f"Canonical source: {path_utils.to_repo_relative(CANONICAL, repo_root=REPO_ROOT)}")


if __name__ == "__main__":
    main()
