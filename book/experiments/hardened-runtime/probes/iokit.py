"""IOKit probes (planned; no runtime coverage yet)."""

from __future__ import annotations

from pathlib import Path
from typing import List

from book.api.runtime import workflow


def build_profiles(_sb_dir: Path) -> List[workflow.ProfileSpec]:
    return []
