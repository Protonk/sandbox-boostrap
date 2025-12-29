"""Instruction, offset, and pointer scan tasks.

These tasks drive pattern-based searches (offset immediates, ADRP+ADD sequences,
pointer windows) that are too verbose to do by hand in Ghidra. The outputs are
structured for later filtering and shape snapshots.
"""

from __future__ import annotations

from .base import TaskConfig

GROUP = "scan"
# Scans are intentionally parameterized via script args; task names pin common presets.

# Task names are used in output paths and fixtures; keep them stable once published.
TASKS = [
    TaskConfig(
        name="kernel-collection-offset-scan",
        script="kernel_offset_inst_scan.py",
        import_target="kernel_collection",
        description="Scan the KC for instructions referencing a specific immediate offset.",
        group=GROUP,
    ),
    # Offset-specific tasks pin known struct fields; the name encodes the offset for clarity.
    TaskConfig(
        name="kernel-collection-offset-scan-0x150",
        script="kernel_offset_inst_scan.py",
        import_target="kernel_collection",
        description="Scan the KC for instructions referencing offset 0x150.",
        group=GROUP,
    ),
    TaskConfig(
        name="kernel-collection-offset-scan-0x74",
        script="kernel_offset_inst_scan.py",
        import_target="kernel_collection",
        description="Scan the KC for instructions referencing offset 0x74.",
        group=GROUP,
    ),
    TaskConfig(
        name="kernel-collection-offset-scan-0x9a4",
        script="kernel_offset_inst_scan.py",
        import_target="kernel_collection",
        description="Scan the KC for instructions referencing offset 0x9a4.",
        group=GROUP,
    ),
    TaskConfig(
        name="kernel-offset-intersect",
        script="kernel_offset_intersect.py",
        import_target="kernel_collection",
        description="Intersect multiple offset scan outputs by function.",
        group=GROUP,
    ),
    TaskConfig(
        name="kernel-adrp-add-scan",
        script="kernel_adrp_add_scan.py",
        import_target="kernel",
        description="Locate ADRP+ADD/SUB sequences that materialize a target address.",
        group=GROUP,
    ),
    TaskConfig(
        name="kernel-adrp-add-kc-0xfffffe0007005f98",
        script="kernel_adrp_add_scan.py",
        import_target="kernel_collection",
        description="Locate ADRP+ADD sequences for a KC anchor address.",
        # ADRP materializes page bases; ADD/SUB then applies the within-page offset.
        group=GROUP,
    ),
    TaskConfig(
        name="kernel-adrp-ldr-scan",
        script="kernel_adrp_ldr_scan.py",
        import_target="kernel",
        description="Locate ADRP+LDR sequences that load a target address.",
        group=GROUP,
    ),
    TaskConfig(
        name="sandbox-kext-adrp-add-scan",
        script="kernel_adrp_add_scan.py",
        import_target="sandbox_kext",
        description="Locate ADRP+ADD/SUB sequences in sandbox_kext for a target address.",
        group=GROUP,
    ),
    TaskConfig(
        name="sandbox-kext-adrp-ldr-scan",
        script="kernel_adrp_ldr_scan.py",
        import_target="sandbox_kext",
        description="Locate ADRP+LDR sequences in sandbox_kext for a target address.",
        group=GROUP,
    ),
    TaskConfig(
        name="sandbox-kext-adrp-ldr-got-scan",
        script="kernel_adrp_ldr_scan.py",
        import_target="sandbox_kext",
        description="Locate ADRP+LDR sequences in sandbox_kext that land in __auth_got.",
        group=GROUP,
    ),
    TaskConfig(
        name="kernel-imm-search",
        script="kernel_imm_search.py",
        import_target="kernel",
        description="Search instructions for a given immediate (scalar) value.",
        group=GROUP,
    ),
    TaskConfig(
        name="kernel-collection-imm-search",
        script="kernel_imm_search.py",
        import_target="kernel_collection",
        description="Search KC instructions for a given immediate (scalar) value.",
        group=GROUP,
    ),
    TaskConfig(
        name="sandbox-kext-imm-search",
        script="kernel_imm_search.py",
        import_target="sandbox_kext",
        description="Search sandbox_kext instructions for a given immediate value.",
        group=GROUP,
    ),
    TaskConfig(
        name="kernel-arm-const-base-scan",
        script="kernel_arm_const_base_scan.py",
        import_target="kernel",
        description="Scan ADRP base materializations into a target address range.",
        group=GROUP,
    ),
    TaskConfig(
        name="sandbox-kext-arm-const-base-scan",
        script="kernel_arm_const_base_scan.py",
        import_target="sandbox_kext",
        description="Scan ADRP base materializations into a target address range in sandbox_kext.",
        group=GROUP,
    ),
    TaskConfig(
        name="kernel-field2-mask-scan",
        script="kernel_field2_mask_scan.py",
        import_target="kernel",
        description="Search sandbox code for mask immediates (field2/filter_arg flags).",
        group=GROUP,
    ),
    TaskConfig(
        name="sandbox-kext-offset-scan",
        script="kernel_offset_inst_scan.py",
        import_target="sandbox_kext",
        description="Scan sandbox_kext for instructions referencing a specific immediate offset.",
        group=GROUP,
    ),
    TaskConfig(
        name="sandbox-kext-offset-scan-0x150",
        script="kernel_offset_inst_scan.py",
        import_target="sandbox_kext",
        description="Scan sandbox_kext for instructions referencing offset 0x150.",
        group=GROUP,
    ),
    TaskConfig(
        name="sandbox-kext-pointer-value-scan",
        script="kernel_pointer_value_scan.py",
        import_target="sandbox_kext",
        description="Scan sandbox_kext memory for a specific pointer value.",
        group=GROUP,
    ),
    TaskConfig(
        name="page-ref-251ee0",
        script="kernel_page_ref_scan.py",
        import_target="kernel",
        description="Scan kernel pages around address 0xffffff8000251ee0.",
        group=GROUP,
    ),
    TaskConfig(
        name="x86-page-251ee0",
        script="kernel_x86_page_scan.py",
        import_target="kernel",
        description="Scan x86 KC pages around address 0xffffff8000251ee0.",
        group=GROUP,
    ),
]
