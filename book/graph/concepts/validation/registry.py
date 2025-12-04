"""
Central registry for validation jobs and a small helper API for the validation driver.

Jobs are registered close to their decode/ingestion logic; the driver imports
those modules for side-effect registration and then selects/runs jobs by id/tag.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Any

# Repository root (book/..)
ROOT = Path(__file__).resolve().parents[4]


@dataclass
class ValidationJob:
    id: str
    runner: Callable[[], Dict[str, Any] | None]
    inputs: List[str] = field(default_factory=list)
    outputs: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    description: str = ""

    def expanded_inputs(self) -> List[Path]:
        """Expand input patterns relative to repo root."""
        matches: List[Path] = []
        for pattern in self.inputs:
            path = Path(pattern)
            if not path.is_absolute():
                path = ROOT / pattern
            # Support bare directories and glob patterns
            if any(ch in path.name for ch in ["*", "?", "["]):
                matches.extend(Path(path.parent).glob(path.name))
            elif path.is_dir():
                matches.extend(sorted(path.iterdir()))
            else:
                matches.append(path)
        return matches

    def has_inputs(self) -> bool:
        if not self.inputs:
            return True
        return any(p.exists() for p in self.expanded_inputs())


JOBS: List[ValidationJob] = []

# Modules that self-register jobs on import.
JOB_MODULES = [
    "book.graph.concepts.validation.vocab_extraction",
    "book.graph.concepts.validation.fixtures_job",
]


def register(job: ValidationJob) -> None:
    """Register a job; ids must be unique."""
    if any(existing.id == job.id for existing in JOBS):
        raise ValueError(f"duplicate ValidationJob id: {job.id}")
    JOBS.append(job)


def load_all_jobs() -> List[ValidationJob]:
    """Import known job modules and return the registry."""
    for mod in JOB_MODULES:
        importlib.import_module(mod)
    return JOBS
