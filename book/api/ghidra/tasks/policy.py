"""Policy graph and mac_policy related tasks.

These tasks focus on mac_policy registration, operation tables, and policy-graph
dispatchers. They provide the static anchoring needed to map ops/filters back to
kernel behavior.
"""

from __future__ import annotations

from .base import TaskConfig

GROUP = "policy"
# Policy tasks often depend on KC analysis; keep KC targets explicit.

# Task names here anchor experiments and fixtures; prefer aliases over renames.
TASKS = [
    TaskConfig(
        name="kernel-tag-switch",
        script="kernel_tag_switch.py",
        import_target="kernel",
        description="Locate PolicyGraph dispatcher/tag switch inside the KC.",
        group=GROUP,
    ),
    TaskConfig(
        name="kernel-tag-switch-kc",
        script="kernel_tag_switch.py",
        import_target="kernel_collection",
        description="Locate PolicyGraph dispatcher/tag switch inside the KC.",
        group=GROUP,
    ),
    TaskConfig(
        name="find-field2-evaluator",
        script="find_field2_evaluator.py",
        import_target="kernel_collection",
        description="Find field2 evaluator helpers and dump summaries.",
        group=GROUP,
    ),
    TaskConfig(
        name="kernel-op-table",
        script="kernel_op_table.py",
        import_target="kernel",
        description="Recover operation pointer table entries from the KC.",
        # The op table is a pointer table in kernel text; address normalization matters.
        group=GROUP,
    ),
    TaskConfig(
        name="kernel-mac-policy-register",
        script="mac_policy_register_scan.py",
        import_target="kernel_collection",
        description="Locate mac_policy_register call sites and recover arg pointers in the KC.",
        group=GROUP,
    ),
    TaskConfig(
        name="kernel-collection-syscall-code-scan",
        script="sandbox_syscall_code_scan.py",
        import_target="kernel_collection",
        description="Scan the KC for compare-like uses of a syscall call code.",
        group=GROUP,
    ),
    TaskConfig(
        name="kernel-mac-policy-register-anchor",
        script="kernel_anchor_mac_policy_register.py",
        import_target="kernel_collection",
        description="Rename and apply signature to mac_policy_register anchor in the KC.",
        group=GROUP,
    ),
    TaskConfig(
        name="kernel-mac-policy-register-instances",
        script="kernel_mac_policy_register_instances.py",
        import_target="kernel_collection",
        description="Recover mac_policy_register instances and decode mac_policy_conf fields.",
        group=GROUP,
    ),
    TaskConfig(
        name="sandbox-kext-conf-scan",
        script="sandbox_kext_conf_scan.py",
        import_target="sandbox_kext",
        description="Scan sandbox kext data segments for mac_policy_conf candidates.",
        group=GROUP,
    ),
    TaskConfig(
        name="sandbox-kext-mac-policy-register",
        script="mac_policy_register_scan.py",
        import_target="sandbox_kext",
        description="Locate mac_policy_register call sites inside sandbox_kext.bin.",
        group=GROUP,
    ),
    TaskConfig(
        name="sandbox-kext-op-table",
        script="kernel_op_table.py",
        import_target="sandbox_kext",
        description="Surface pointer-table candidates inside sandbox_kext segments.",
        group=GROUP,
    ),
    TaskConfig(
        name="sandbox-kext-syscall-code-scan",
        script="sandbox_syscall_code_scan.py",
        import_target="sandbox_kext",
        description="Scan sandbox_kext for compare-like uses of a syscall call code.",
        group=GROUP,
    ),
    TaskConfig(
        name="amfi-kext-mac-policy-register",
        script="mac_policy_register_scan.py",
        import_target="amfi_kext",
        description="Locate mac_policy_register call sites inside AMFI kext slice.",
        group=GROUP,
    ),
]
