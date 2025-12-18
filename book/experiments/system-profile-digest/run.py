#!/usr/bin/env python3
"""
Regenerate experiment-local digests for the curated canonical system profile blobs.

This writes `book/experiments/system-profile-digest/out/digests.json`, which is then
normalized into validation IR by the job `experiment:system-profile-digest` and
promoted into `book/graph/mappings/system_profiles/digests.json`.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Final


def main() -> None:
    root: Final[Path] = Path(__file__).resolve().parents[3]
    out_rel: Final[Path] = Path("book/experiments/system-profile-digest/out/digests.json")
    (root / out_rel).parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        sys.executable,
        "-m",
        "book.api.profile_tools",
        "digest",
        "system-profiles",
        "--out",
        str(out_rel),
    ]
    subprocess.check_call(cmd, cwd=root)


if __name__ == "__main__":
    main()
