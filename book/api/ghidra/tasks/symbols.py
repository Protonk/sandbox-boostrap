"""Symbol and string inventory tasks.

These tasks emit symbol and string tables for later cross-referencing. The
output format is intentionally simple JSON so shape snapshots can guard against
regressions even when the underlying Ghidra project isn't available.
"""

from __future__ import annotations

from .base import TaskConfig
from .. import paths

GROUP = "symbols"
# The KC (BootKernelCollection.kc) is the canonical slice for sandbox symbols on Sonoma,
# while kernel/sandbox_kext targets are kept for cross-checks and deltas.

# Task names here are referenced directly by fixture manifests; keep them stable.
TASKS = [
    TaskConfig(
        name="kernel-symbols",
        script="kernel_symbols.py",
        import_target="kernel",
        description="Import KC and dump symbols/strings for com.apple.security.sandbox.",
        # Symbols feed multiple experiments; route to the shared kernel-symbols output root.
        out_root=paths.KERNEL_SYMBOLS_OUT_ROOT,
        group=GROUP,
    ),
    TaskConfig(
        name="kernel-collection-symbols",
        script="kernel_symbols.py",
        import_target="kernel_collection",
        description="Dump symbols/strings for com.apple.security.sandbox in the KC.",
        group=GROUP,
    ),
    TaskConfig(
        name="sandbox-kext-symbols",
        script="kernel_symbols.py",
        import_target="sandbox_kext",
        description="Emit symbol/string tables for sandbox_kext.",
        group=GROUP,
    ),
]
