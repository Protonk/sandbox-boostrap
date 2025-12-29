"""Disassembly, window dumps, and function metadata tasks.

These tasks provide small, reviewable disassembly windows and function metadata
that are stable enough to snapshot in tests. Use them when you need a precise
instruction-level anchor rather than a broad scan.
"""

from __future__ import annotations

from .base import TaskConfig

GROUP = "disasm"
# Window dumps are intentionally small to keep outputs diff-friendly and deterministic.

# Task names here are embedded in dump paths; renaming breaks downstream references.
TASKS = [
    TaskConfig(
        name="kernel-function-dump",
        script="kernel_function_dump.py",
        import_target="kernel",
        description="Dump disassembly for specified functions/addresses.",
        group=GROUP,
    ),
    TaskConfig(
        name="function-dump",
        script="kernel_function_dump.py",
        import_target="kernel",
        description="Dump disassembly for specific functions/addresses (legacy name).",
        group=GROUP,
    ),
    TaskConfig(
        name="kernel-collection-function-dump",
        script="kernel_function_dump.py",
        import_target="kernel_collection",
        description="Dump disassembly for specified functions/addresses in the KC.",
        group=GROUP,
    ),
    TaskConfig(
        name="kernel-function-dump-kc",
        script="kernel_function_dump.py",
        import_target="kernel_collection",
        description="Dump disassembly for KC functions/addresses (legacy name).",
        group=GROUP,
    ),
    TaskConfig(
        name="kernel-collection-addr-window-dump",
        script="kernel_addr_window_dump.py",
        import_target="kernel_collection",
        description="Dump an instruction window around a KC address.",
        group=GROUP,
    ),
    TaskConfig(
        name="kernel-collection-addr-window-disasm",
        script="kernel_addr_window_disasm.py",
        import_target="kernel_collection",
        description="Disassemble a fixed instruction window around a KC address.",
        group=GROUP,
    ),
    TaskConfig(
        name="kernel-block-disasm",
        script="kernel_block_disasm.py",
        import_target="kernel",
        description="Disassemble across matching KC memory blocks (prepares follow-on scans).",
        group=GROUP,
    ),
    TaskConfig(
        name="kernel-block-disasm-kc",
        script="kernel_block_disasm.py",
        import_target="kernel_collection",
        description="Disassemble across matching KC memory blocks.",
        group=GROUP,
    ),
    TaskConfig(
        name="kernel-function-info",
        script="kernel_function_info.py",
        import_target="kernel",
        description="Emit metadata for specified functions (callers, callees, size).",
        group=GROUP,
    ),
    TaskConfig(
        name="kernel-collection-function-info",
        script="kernel_function_info.py",
        import_target="kernel_collection",
        description="Emit metadata for specified functions in the KC (callers, callees, size).",
        group=GROUP,
    ),
    TaskConfig(
        name="kernel-function-info-kc",
        script="kernel_function_info.py",
        import_target="kernel_collection",
        description="Emit metadata for specified KC functions (legacy name).",
        group=GROUP,
    ),
    TaskConfig(
        name="kernel-function-info-kc-top10",
        script="kernel_function_info.py",
        import_target="kernel_collection",
        description="Emit KC function metadata for a top-10 callsite list.",
        # This is a curated slice used to keep output size bounded in regression tests.
        group=GROUP,
    ),
    TaskConfig(
        name="sandbox-kext-addr-window-dump",
        script="kernel_addr_window_dump.py",
        import_target="sandbox_kext",
        description="Dump an instruction window around a sandbox_kext address.",
        group=GROUP,
    ),
    TaskConfig(
        name="sandbox-kext-block-disasm",
        script="kernel_block_disasm.py",
        import_target="sandbox_kext",
        description="Disassemble across matching sandbox kext blocks (e.g., __stubs).",
        group=GROUP,
    ),
    TaskConfig(
        name="sandbox-kext-function-dump",
        script="kernel_function_dump.py",
        import_target="sandbox_kext",
        description="Dump disassembly for specified functions/addresses in sandbox_kext.",
        group=GROUP,
    ),
    TaskConfig(
        name="amfi-kext-block-disasm",
        script="kernel_block_disasm.py",
        import_target="amfi_kext",
        description="Disassemble across matching AMFI kext blocks (prepares follow-on scans).",
        group=GROUP,
    ),
    TaskConfig(
        name="amfi-kext-function-dump",
        script="kernel_function_dump.py",
        import_target="amfi_kext",
        description="Dump disassembly for specified AMFI kext functions/addresses.",
        group=GROUP,
    ),
]
