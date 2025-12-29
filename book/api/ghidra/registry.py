"""Task registry helpers grouped by functional area.

Registry access is intentionally lightweight: it provides stable names for CLI
enumeration and keeps tests aligned with the manifest fixtures.
"""

from __future__ import annotations

from typing import Dict, List

from .tasks import TaskConfig, task_groups, tasks_by_name


def list_groups() -> List[str]:
    # Sorting keeps CLI output deterministic for snapshot-style tests.
    return sorted(task_groups().keys())


def list_tasks() -> List[str]:
    # Task names are treated as API keys; list them in a stable order.
    return sorted(tasks_by_name().keys())


def tasks_for_group(group: str) -> List[TaskConfig]:
    groups = task_groups()
    if group not in groups:
        raise KeyError(f"unknown task group: {group}")
    # Return a copy to prevent callers from mutating global task state.
    return list(groups[group])


def all_tasks() -> Dict[str, TaskConfig]:
    return tasks_by_name()
