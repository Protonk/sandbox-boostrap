"""
Unified runtime tooling for the Sonoma baseline.

This package exposes a *public* repo-wide API surface for producing and consuming
runtime evidence in a tier-disciplined way on this host baseline.

Stability contract:
- The supported import surface is this package (`book.api.runtime`).
- The supported symbols are listed in `__all__` and documented in
  `book/api/runtime/README.md`.
- Submodules exist for internal implementation and legacy helpers, but they are
  not part of the stable public API unless exported here.

`__all__` is the explicit public surface for `from ... import *` and
acts as a signal to readers about what we intend to keep stable.
"""

from __future__ import annotations

from .execution.service import (
    RunBundle,
    ValidationResult,
    emit_promotion_packet,
    load_bundle,
    open_bundle_unverified,
    reindex_bundle,
    run_plan,
    runtime_status,
    validate_bundle,
)
from .execution.channels.spec import ChannelName, ChannelSpec, LockMode
from .analysis.inventory import build_runtime_inventory
from .analysis.links import (
    list_linked_expectations,
    list_linked_profiles,
    load_runtime_links,
    resolve_expectation_link,
    resolve_profile_link,
)
from .analysis.op_summary import (
    build_op_runtime_summary,
    summarize_ops_from_bundle,
    summarize_ops_from_packet,
    write_op_runtime_summary,
)
from .plans.builder import PlanBuildResult, build_plan_from_template, list_plan_templates, load_plan_template
from .plans.loader import lint_plan, list_plans, load_plan, plan_digest
from .plans.registry import (
    lint_registry,
    list_profiles,
    list_probes,
    list_registries,
    resolve_probe,
    resolve_profile,
)

# Group exports to mirror README sections and keep diffs stable.
__all__ = [
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
    # Runtime links
    "load_runtime_links",
    "list_linked_profiles",
    "list_linked_expectations",
    "resolve_profile_link",
    "resolve_expectation_link",
    # Op summary helpers
    "build_op_runtime_summary",
    "summarize_ops_from_bundle",
    "summarize_ops_from_packet",
    "write_op_runtime_summary",
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
