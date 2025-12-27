"""
Unified runtime tooling for the Sonoma baseline.

This package consolidates:
- Runtime observation/normalization helpers.
- Runtime mapping builders + story adapters.
- Derived projections and workflow helpers.
- The runtime harness runner/golden generator.

Preferred imports:
- from book.api.runtime_tools import core, harness, mapping, workflow, api
- from book.api.runtime_tools.core import models, normalize, contract
- from book.api.runtime_tools.api import run_plan, load_bundle, validate_bundle
  (plan-based execution + artifact bundle handling).

Keep top-level convenience exports intentionally small and stable.
"""

from __future__ import annotations

from . import api as api  # noqa: F401
from . import cli as cli  # noqa: F401
from . import core as core  # noqa: F401
from . import harness as harness  # noqa: F401
from . import mapping as mapping  # noqa: F401
from . import workflow as workflow  # noqa: F401

from .core.models import (  # noqa: F401
    WORLD_ID,
    RuntimeCut,
    RuntimeObservation,
    RuntimeRun,
)
from .core.normalize import (  # noqa: F401
    derive_expectation_id,
    make_scenario_id,
    normalize_matrix,
    normalize_matrix_paths,
    normalize_metadata_results,
    observation_to_dict,
    write_matrix_observations,
    write_metadata_observations,
)
from .mapping.story import (  # noqa: F401
    build_story,
    story_to_coverage,
    story_to_signatures,
    write_story,
)
from .mapping.views import (  # noqa: F401
    CalloutOracleRow,
    CalloutVsSyscallRow,
    build_callout_oracle,
    build_callout_vs_syscall,
)
from .workflow import (  # noqa: F401
    build_cut,
    promote_cut,
    run_from_matrix,
)
from .api import (  # noqa: F401
    RunBundle,
    ValidationResult,
    run_plan,
    load_bundle,
    validate_bundle,
    emit_promotion_packet,
)
from .inventory import (  # noqa: F401
    build_runtime_inventory,
)
from .plan import (  # noqa: F401
    load_plan,
    plan_digest,
)
from .registry import (  # noqa: F401
    list_registries,
    list_probes,
    list_profiles,
    resolve_probe,
    resolve_profile,
)

__all__ = [
    "cli",
    "core",
    "harness",
    "mapping",
    "workflow",
    "api",
    "WORLD_ID",
    "RuntimeCut",
    "RuntimeObservation",
    "RuntimeRun",
    "derive_expectation_id",
    "make_scenario_id",
    "normalize_matrix",
    "normalize_matrix_paths",
    "normalize_metadata_results",
    "observation_to_dict",
    "write_matrix_observations",
    "write_metadata_observations",
    "build_story",
    "write_story",
    "story_to_coverage",
    "story_to_signatures",
    "CalloutOracleRow",
    "CalloutVsSyscallRow",
    "build_callout_oracle",
    "build_callout_vs_syscall",
    "build_cut",
    "promote_cut",
    "run_from_matrix",
    "RunBundle",
    "ValidationResult",
    "run_plan",
    "load_bundle",
    "validate_bundle",
    "emit_promotion_packet",
    "build_runtime_inventory",
    "load_plan",
    "plan_digest",
    "list_registries",
    "list_probes",
    "list_profiles",
    "resolve_probe",
    "resolve_profile",
]
