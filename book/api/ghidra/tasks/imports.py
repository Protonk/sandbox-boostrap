"""Import and GOT/linkage related tasks.

These tasks focus on import tables, stubs, and GOT references so we can
attribute external calls to specific symbols or dyld linkage mechanisms.
"""

from __future__ import annotations

from .base import TaskConfig

GROUP = "imports"
# KC imports capture the main kernel text, while kext slices surface sandbox- and AMFI-specific linkage.

# Task list doubles as documentation for CLI output; keep names stable for fixtures.
TASKS = [
    TaskConfig(
        name="kernel-imports",
        script="kernel_imports_scan.py",
        import_target="kernel",
        description="Enumerate external symbols/imports and their references.",
        group=GROUP,
    ),
    TaskConfig(
        name="kernel-collection-imports",
        script="kernel_imports_scan.py",
        import_target="kernel_collection",
        description="Enumerate external symbols/imports and their references in the KC.",
        group=GROUP,
    ),
    TaskConfig(
        name="kernel-collection-stub-got-map",
        script="kernel_stub_got_map.py",
        import_target="kernel_collection",
        description="Map KC stubs/trampolines to GOT entries (auth_got/auth_ptr/got).",
        # PAC-enabled GOT slots appear under __auth_got; mapping them preserves call provenance.
        group=GROUP,
    ),
    TaskConfig(
        name="sandbox-kext-stub-got-map",
        script="kernel_stub_got_map.py",
        import_target="sandbox_kext",
        description="Map sandbox kext stubs to GOT entries (auth_got/auth_ptr/got).",
        group=GROUP,
    ),
    TaskConfig(
        name="sandbox-kext-got-ref-sweep",
        script="kernel_got_ref_sweep.py",
        import_target="sandbox_kext",
        description="Define GOT entries and collect references in sandbox_kext.",
        group=GROUP,
    ),
    TaskConfig(
        name="sandbox-kext-got-load-sweep",
        script="kernel_got_load_sweep.py",
        import_target="sandbox_kext",
        description="Scan code for GOT loads or direct refs in sandbox_kext.",
        group=GROUP,
    ),
    TaskConfig(
        name="amfi-kext-got-ref-sweep",
        script="kernel_got_ref_sweep.py",
        import_target="amfi_kext",
        description="Define GOT entries and collect references in AMFI kext slice.",
        group=GROUP,
    ),
    TaskConfig(
        name="amfi-kext-got-load-sweep",
        script="kernel_got_load_sweep.py",
        import_target="amfi_kext",
        description="Scan code for GOT loads or direct refs in AMFI kext slice.",
        group=GROUP,
    ),
]
