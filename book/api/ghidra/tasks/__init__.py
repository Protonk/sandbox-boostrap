"""Functional task groups for Ghidra headless runs.

The grouping is a human-facing affordance for the CLI and README examples, not
an execution requirement. Task names remain the canonical identifiers used by
fixtures and shape manifests.
"""

from __future__ import annotations

from typing import Dict, Iterable, List

from .base import TaskConfig
from .data import TASKS as DATA_TASKS
from .disasm import TASKS as DISASM_TASKS
from .imports import TASKS as IMPORT_TASKS
from .policy import TASKS as POLICY_TASKS
from .scan import TASKS as SCAN_TASKS
from .symbols import TASKS as SYMBOL_TASKS
from .xref import TASKS as XREF_TASKS


# Keep groups explicit so ordering stays predictable in CLI output and docs.
TASK_GROUPS: Dict[str, List[TaskConfig]] = {
    "symbols": SYMBOL_TASKS,
    "imports": IMPORT_TASKS,
    "disasm": DISASM_TASKS,
    "scan": SCAN_TASKS,
    "xref": XREF_TASKS,
    "policy": POLICY_TASKS,
    "data": DATA_TASKS,
}


def all_tasks() -> List[TaskConfig]:
    tasks: List[TaskConfig] = []
    for group in TASK_GROUPS.values():
        tasks.extend(group)
    return tasks


def task_groups() -> Dict[str, List[TaskConfig]]:
    return {name: list(tasks) for name, tasks in TASK_GROUPS.items()}


def tasks_by_name() -> Dict[str, TaskConfig]:
    # Name collisions are treated as a configuration error; last writer wins.
    # Keeping a single source of truth here makes that failure mode visible.
    return {task.name: task for task in all_tasks()}
