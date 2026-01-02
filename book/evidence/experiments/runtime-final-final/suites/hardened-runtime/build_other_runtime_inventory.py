#!/usr/bin/env python3
"""Build an inventory of other runtime tooling and evidence channels."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[5]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api.runtime.analysis import inventory as runtime_inventory  # noqa: E402

OUT_PATH = REPO_ROOT / "book/evidence/experiments/runtime-final-final/suites/hardened-runtime/other_runtime_inventory.json"


def main() -> int:
    runtime_inventory.build_runtime_inventory(repo_root=REPO_ROOT, out_path=OUT_PATH)
    print(f"[+] wrote {OUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
