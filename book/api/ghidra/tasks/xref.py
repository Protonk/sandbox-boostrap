"""Address lookup, xrefs, and related linkage tasks.

These tasks turn raw addresses or constants into context: function names,
callers, and data blocks. They are the primary glue between static offsets and
human-readable provenance.
"""

from __future__ import annotations

from .base import TaskConfig

GROUP = "xref"
# Xref tasks are often used interactively; keep their outputs small and direct.

# Task names are fixtures keys; keep aliases instead of renaming.
TASKS = [
    TaskConfig(
        name="kernel-string-refs",
        script="kernel_string_refs.py",
        import_target="kernel",
        description="Resolve references to sandbox strings and AppleMatch imports in the KC.",
        group=GROUP,
    ),
    TaskConfig(
        name="kernel-string-refs-kc",
        script="kernel_string_refs.py",
        import_target="kernel_collection",
        description="Resolve references to sandbox strings inside the KC.",
        group=GROUP,
    ),
    TaskConfig(
        name="kernel-collection-addr-lookup",
        script="kernel_addr_lookup.py",
        import_target="kernel_collection",
        description="Lookup KC addresses/offsets and report functions/callers.",
        group=GROUP,
    ),
    TaskConfig(
        name="kernel-addr-lookup-kc",
        script="kernel_addr_lookup.py",
        import_target="kernel_collection",
        description="Lookup KC addresses/offsets for specialized reports.",
        group=GROUP,
    ),
    TaskConfig(
        name="kernel-collection-list-head-xref",
        script="kernel_list_head_xref.py",
        import_target="kernel_collection",
        description="Xref a KC list-head address and group refs by function.",
        group=GROUP,
    ),
    TaskConfig(
        name="kernel-collection-store-provenance",
        script="kernel_store_provenance.py",
        import_target="kernel_collection",
        description="Summarize one-step register provenance for a store instruction.",
        group=GROUP,
    ),
    TaskConfig(
        name="kernel-collection-id-builder-trace",
        script="kernel_id_builder_trace.py",
        import_target="kernel_collection",
        description="Trace list-head and writer candidates for id builders in the KC.",
        group=GROUP,
    ),
    TaskConfig(
        name="kernel-collection-string-call-sites",
        script="kernel_string_call_sites.py",
        import_target="kernel_collection",
        description="Find functions referencing strings and list call sites in the KC.",
        group=GROUP,
    ),
    TaskConfig(
        name="kernel-collection-jump-table-read",
        script="kernel_jump_table_read.py",
        import_target="kernel_collection",
        description="Read a signed-32 jump table and resolve targets in the KC.",
        group=GROUP,
    ),
    TaskConfig(
        name="kernel-collection-stub-call-sites",
        script="kernel_stub_call_sites.py",
        import_target="kernel_collection",
        description="Scan KC for BL/B call sites targeting stub/trampoline addresses.",
        group=GROUP,
    ),
    TaskConfig(
        name="kernel-addr-lookup",
        script="kernel_addr_lookup.py",
        import_target="kernel",
        description="Lookup file offsets/constants to map to addresses/functions/callers.",
        group=GROUP,
    ),
    TaskConfig(
        name="addr-lookup-table-page",
        script="kernel_addr_lookup.py",
        import_target="kernel",
        description="Lookup addresses for table-page related addresses.",
        # Table-page lookups anchor negative signed addresses back to KC space.
        group=GROUP,
    ),
    TaskConfig(
        name="sandbox-kext-addr-lookup",
        script="kernel_addr_lookup.py",
        import_target="sandbox_kext",
        description="Lookup addresses/constants inside sandbox_kext.",
        group=GROUP,
    ),
    TaskConfig(
        name="kernel-jump-table-dump-kc",
        script="kernel_jump_table_dump.py",
        import_target="kernel_collection",
        description="Dump jump-table entries for KC dispatcher candidates.",
        group=GROUP,
    ),
    TaskConfig(
        name="sandbox-kext-jump-table-dump",
        script="kernel_jump_table_dump.py",
        import_target="sandbox_kext",
        description="Dump jump-table entries for sandbox_kext dispatcher candidates.",
        group=GROUP,
    ),
    TaskConfig(
        name="sandbox-kext-jump-table-read",
        script="kernel_jump_table_read.py",
        import_target="sandbox_kext",
        description="Read a signed-32 jump table and resolve targets in sandbox_kext.",
        group=GROUP,
    ),
    TaskConfig(
        name="sandbox-kext-string-refs",
        script="kernel_string_refs.py",
        import_target="sandbox_kext",
        description="Resolve references to key sandbox strings inside sandbox_kext.bin.",
        group=GROUP,
    ),
]
