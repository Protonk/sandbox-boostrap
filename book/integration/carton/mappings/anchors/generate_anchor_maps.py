#!/usr/bin/env python3
"""
Regenerate anchor mappings for this world (deterministic entrypoint).

This is the supported way to refresh anchor mappings under `book/integration/carton/bundle/relationships/mappings/anchors/`.
It enforces the "single source of truth + generated compatibility view" contract:

- Canonical: `anchor_ctx_filter_map.json`
- Compatibility: `anchor_filter_map.json` (derived, lossy, conservative)

Do not hand-edit either mapping; update generators and rerun this script.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[5]
SCRIPT_ROOT = Path(__file__).resolve().parent


def main() -> None:
    cmds = [
        [sys.executable, str(SCRIPT_ROOT / "generate_anchor_ctx_filter_map.py")],
        [sys.executable, str(SCRIPT_ROOT / "generate_anchor_filter_map.py")],
    ]
    for cmd in cmds:
        subprocess.check_call(cmd, cwd=REPO_ROOT)


if __name__ == "__main__":
    main()
