"""Registry-driven pipeline runner for CARTON."""

from __future__ import annotations

import os
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set

from book.api import path_utils
from book.integration.carton.core.models import Job, Registry


@dataclass(frozen=True)
class JobRun:
    job_id: str
    ran: bool
    outputs: List[str]


class Pipeline:
    def __init__(self, registry: Registry, repo_root: Path) -> None:
        self._registry = registry
        self._repo_root = repo_root
        self._artifacts = registry.artifact_index()
        self._jobs = registry.job_index()
        self._output_to_job = self._build_output_index()

    def _build_output_index(self) -> Dict[str, str]:
        output_map: Dict[str, str] = {}
        for job in self._registry.jobs:
            for out in self._resolve_refs(job.outputs):
                if out in output_map:
                    raise ValueError(f"duplicate output path in registry: {out}")
                output_map[out] = job.id
        return output_map

    def _resolve_refs(self, refs: Iterable[str]) -> List[str]:
        resolved: List[str] = []
        for ref in refs:
            art = self._artifacts.get(ref)
            resolved.append(art.path if art else ref)
        return resolved

    def job_inputs(self, job: Job) -> List[str]:
        return self._resolve_refs(job.inputs)

    def job_outputs(self, job: Job) -> List[str]:
        return self._resolve_refs(job.outputs)

    def job_dependencies(self, job: Job) -> Set[str]:
        deps: Set[str] = set()
        for ref in self.job_inputs(job):
            owner = self._output_to_job.get(ref)
            if owner:
                deps.add(owner)
        return deps

    def _toposort(self, job_ids: Iterable[str]) -> List[str]:
        wanted = set(job_ids)
        deps: Dict[str, Set[str]] = {jid: self.job_dependencies(self._jobs[jid]) for jid in wanted}
        for jid in list(deps.keys()):
            deps[jid] = {d for d in deps[jid] if d in wanted}

        incoming = {jid: len(dep) for jid, dep in deps.items()}
        queue = deque([jid for jid, count in incoming.items() if count == 0])
        order: List[str] = []
        while queue:
            jid = queue.popleft()
            order.append(jid)
            for other in wanted:
                if jid in deps.get(other, set()):
                    deps[other].remove(jid)
                    incoming[other] -= 1
                    if incoming[other] == 0:
                        queue.append(other)
        if len(order) != len(wanted):
            cycle = sorted(wanted - set(order))
            raise RuntimeError(f"cycle or unresolved dependency in jobs: {cycle}")
        return order

    def expand_job_ids(self, job_ids: Iterable[str]) -> Set[str]:
        wanted = set(job_ids)
        stack = list(wanted)
        while stack:
            jid = stack.pop()
            job = self._jobs.get(jid)
            if not job:
                raise KeyError(f"unknown job id: {jid}")
            for dep in self.job_dependencies(job):
                if dep not in wanted:
                    wanted.add(dep)
                    stack.append(dep)
        return wanted

    def _mtime(self, rel_path: str) -> Optional[float]:
        abs_path = path_utils.ensure_absolute(rel_path, repo_root=self._repo_root)
        if not abs_path.exists():
            return None
        return abs_path.stat().st_mtime

    def needs_run(self, job: Job, *, changed_only: bool) -> bool:
        if job.always_run:
            return True
        if not changed_only:
            return True
        outputs = self.job_outputs(job)
        output_times = [self._mtime(p) for p in outputs]
        if any(t is None for t in output_times):
            return True
        oldest_output = min(t for t in output_times if t is not None)
        for ref in self.job_inputs(job):
            mtime = self._mtime(ref)
            if mtime is not None and mtime > oldest_output:
                return True
        return False

    def run_jobs(
        self,
        job_ids: Iterable[str],
        *,
        changed_only: bool = True,
        quiet: bool = False,
    ) -> List[JobRun]:
        expanded = self.expand_job_ids(job_ids)
        order = self._toposort(expanded)
        results: List[JobRun] = []
        for jid in order:
            job = self._jobs[jid]
            run = self.needs_run(job, changed_only=changed_only)
            outputs = self.job_outputs(job)
            if run:
                if not quiet:
                    print(f"[carton] job {jid}")
                job.runner(self._repo_root)
            results.append(JobRun(job_id=jid, ran=run, outputs=outputs))
        return results

    def graph_lines(self, job_ids: Iterable[str]) -> List[str]:
        lines: List[str] = []
        for jid in self._toposort(job_ids):
            job = self._jobs[jid]
            deps = sorted(self.job_dependencies(job))
            dep_str = f" deps={','.join(deps)}" if deps else ""
            lines.append(f"{jid} [{job.kind}]{dep_str}")
            for out in self.job_outputs(job):
                lines.append(f"  -> {out}")
        return lines

    def explain(self, job_id: str) -> List[str]:
        if job_id not in self._jobs:
            raise KeyError(f"unknown job id: {job_id}")
        job = self._jobs[job_id]
        lines = [f"{job.id} [{job.kind}]", f"{job.description}"]
        lines.append("inputs:")
        for ref in self.job_inputs(job):
            lines.append(f"  - {ref}")
        lines.append("outputs:")
        for ref in self.job_outputs(job):
            lines.append(f"  - {ref}")
        deps = sorted(self.job_dependencies(job))
        if deps:
            lines.append(f"depends_on: {', '.join(deps)}")
        return lines
