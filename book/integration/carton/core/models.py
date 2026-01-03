"""Core data models for CARTON registry and pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional


@dataclass(frozen=True)
class Artifact:
    id: str
    path: str
    role: str
    hash_mode: str
    checks: List[str] = field(default_factory=list)
    schema: Optional[str] = None


@dataclass(frozen=True)
class Job:
    id: str
    kind: str
    description: str
    inputs: List[str]
    outputs: List[str]
    runner: Callable[[Path], None]
    module: Optional[str] = None
    function: Optional[str] = None
    always_run: bool = False


@dataclass(frozen=True)
class Registry:
    artifacts: List[Artifact]
    jobs: List[Job]
    invariants: Dict[str, object]

    def artifact_index(self) -> Dict[str, Artifact]:
        return {art.id: art for art in self.artifacts}

    def job_index(self) -> Dict[str, Job]:
        return {job.id: job for job in self.jobs}

    def jobs_by_kind(self, kind: str) -> List[Job]:
        return [job for job in self.jobs if job.kind == kind]

    def job_ids(self, *, kinds: Optional[Iterable[str]] = None) -> List[str]:
        if not kinds:
            return [job.id for job in self.jobs]
        wanted = set(kinds)
        return [job.id for job in self.jobs if job.kind in wanted]
