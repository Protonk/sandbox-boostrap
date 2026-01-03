"""Validation job runners for CARTON."""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Iterable, Optional

from book.integration.carton.validation import __main__ as validation_cli


def run_validation(
    *,
    ids: Optional[Iterable[str]] = None,
    tags: Optional[Iterable[str]] = None,
    experiments: Optional[Iterable[str]] = None,
    run_all: bool = False,
    skip_missing_inputs: bool = False,
) -> None:
    validation_cli.run_jobs(
        ids=list(ids or []),
        tags=list(tags or []),
        experiments=list(experiments or []),
        run_all=run_all,
        skip_missing_inputs=skip_missing_inputs,
    )


def run_smoke(_repo_root: Path) -> None:
    run_validation(tags=["smoke"], skip_missing_inputs=True)


def make_runner(job_id: str) -> Callable[[Path], None]:
    def _run(_repo_root: Path) -> None:
        run_validation(ids=[job_id], skip_missing_inputs=True)

    return _run
