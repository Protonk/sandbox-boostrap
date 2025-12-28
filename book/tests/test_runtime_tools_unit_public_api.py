from __future__ import annotations

from book.api import runtime_tools as rt


EXPECTED_PUBLIC_EXPORTS = [
    # Channels
    "ChannelName",
    "ChannelSpec",
    "LockMode",
    # Plan/registry discovery
    "load_plan",
    "list_plans",
    "plan_digest",
    "lint_plan",
    "list_registries",
    "list_probes",
    "list_profiles",
    "resolve_probe",
    "resolve_profile",
    "lint_registry",
    # Plan templates
    "list_plan_templates",
    "load_plan_template",
    "build_plan_from_template",
    "PlanBuildResult",
    # Execution + bundle lifecycle
    "RunBundle",
    "ValidationResult",
    "run_plan",
    "load_bundle",
    "validate_bundle",
    "emit_promotion_packet",
    "runtime_status",
    "open_bundle_unverified",
    "reindex_bundle",
    # Inventory (repo sweep)
    "build_runtime_inventory",
]


def test_runtime_tools_public_api_exports_stable():
    assert rt.__all__ == EXPECTED_PUBLIC_EXPORTS


def test_runtime_tools_public_api_exports_resolve():
    missing = [name for name in rt.__all__ if not hasattr(rt, name)]
    assert not missing, f"missing public exports: {missing}"
