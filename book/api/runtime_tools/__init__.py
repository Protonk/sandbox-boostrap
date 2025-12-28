"""
Unified runtime tooling for the Sonoma baseline.

This package exposes a *public* repo-wide API surface for producing and consuming
runtime evidence in a tier-disciplined way on this host baseline.

Stability contract:
- The supported import surface is this package (`book.api.runtime_tools`).
- The supported symbols are listed in `__all__` and documented in
  `book/api/runtime_tools/PUBLIC_API.md`.
- Submodules (e.g. `core/`, `harness/`, `mapping/`, `workflow.py`) exist for
  internal implementation and legacy helpers, but they are not part of the
  stable public API unless exported here.
"""

from __future__ import annotations

from .api import (
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
from .channels.spec import ChannelName, ChannelSpec, LockMode
from .inventory import build_runtime_inventory
from .plan_builder import PlanBuildResult, build_plan_from_template, list_plan_templates, load_plan_template
from .plan import lint_plan, list_plans, load_plan, plan_digest
from .registry import (
    lint_registry,
    list_profiles,
    list_probes,
    list_registries,
    resolve_probe,
    resolve_profile,
)

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
