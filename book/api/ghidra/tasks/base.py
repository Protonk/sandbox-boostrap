"""Task definitions for Ghidra scaffolding and registry.

This module defines the minimal task shape shared by the scaffold, registry,
and CLI. The intent is to keep task metadata small and stable so manifests,
fixtures, and scripts stay aligned across refactors.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .. import paths


@dataclass(frozen=True)
class TaskConfig:
    """Definition of a headless task: which script to run, where to import from, and where to write."""

    # Task names are API keys used in manifests/fixtures; keep them stable.
    name: str
    script: str
    # import_target must match BuildPaths attributes (kernel, kernel_collection, etc.).
    import_target: str
    description: str
    out_root: Path | None = None
    group: str | None = None

    def script_path(self) -> Path:
        # The script path is resolved relative to the repo root so tasks remain portable
        # across different checkout locations and Ghidra user settings directories.
        return paths.SCRIPTS_DIR / self.script
