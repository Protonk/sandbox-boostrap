"""Data definition and table extraction tasks.

These tasks define structured data (tables, pointer windows) and emit compact
JSON summaries suitable for follow-on analysis. They are intentionally small
and deterministic to keep snapshots stable.
"""

from __future__ import annotations

from .base import TaskConfig

GROUP = "data"
# Data tasks tend to mutate the Ghidra listing; prefer running against a disposable project.

# Task names are tied to snapshot fixtures; keep them stable.
TASKS = [
    TaskConfig(
        name="kernel-data-define",
        script="kernel_data_define_and_refs.py",
        import_target="kernel",
        description="Define data at given addresses and dump references (for pointer/table pivots).",
        group=GROUP,
    ),
    TaskConfig(
        name="data-refs-tableptr",
        script="kernel_data_define_and_refs.py",
        import_target="kernel",
        description="Define table pointer data and dump references.",
        # This is a preset with the expected table pointer baked into the run args.
        group=GROUP,
    ),
    TaskConfig(
        name="sandbox-kext-data-define",
        script="kernel_data_define_and_refs.py",
        import_target="sandbox_kext",
        description="Define data at given addresses in sandbox_kext and dump references.",
        group=GROUP,
    ),
    TaskConfig(
        name="kernel-pointer-window-kc",
        script="kernel_pointer_table_window.py",
        import_target="kernel_collection",
        description="Dump a window of KC pointer table entries around an address.",
        group=GROUP,
    ),
    TaskConfig(
        name="kernel-pointer-window-kc-auto",
        script="kernel_pointer_table_window.py",
        import_target="kernel_collection",
        description="Auto-expand a KC pointer window until entries stop resolving.",
        group=GROUP,
    ),
]
