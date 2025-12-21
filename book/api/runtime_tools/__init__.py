"""
Unified runtime tooling for the Sonoma baseline.

This package consolidates:
- Runtime observation/normalization helpers.
- Runtime mapping builders + story adapters.
- Derived projections and pipeline helpers.
- The runtime harness runner/generator.

Preferred imports:
- from book.api.runtime_tools import observations, runtime_contract, mapping_builders
- from book.api.runtime_tools import runtime_story, derived_views, runtime_pipeline
- from book.api.runtime_tools import harness_runner, harness_generate

Keep top-level convenience exports intentionally small and stable.
"""

from __future__ import annotations

from . import cli as cli  # noqa: F401
from . import runtime_contract as runtime_contract  # noqa: F401
from . import observations as observations  # noqa: F401
from . import mapping_builders as mapping_builders  # noqa: F401
from . import runtime_story as runtime_story  # noqa: F401
from . import derived_views as derived_views  # noqa: F401
from . import runtime_pipeline as runtime_pipeline  # noqa: F401
from . import harness_runner as harness_runner  # noqa: F401
from . import harness_generate as harness_generate  # noqa: F401

from .observations import (  # noqa: F401
    WORLD_ID,
    RuntimeObservation,
    derive_expectation_id,
    make_scenario_id,
    normalize_from_paths,
    normalize_metadata_runner_results,
    normalize_runtime_results,
    serialize_observation,
    write_metadata_runner_normalized_events,
    write_normalized_events,
)
from .mapping_builders import (  # noqa: F401
    RUNTIME_LOG_SCHEMA,
    RUNTIME_MAPPING_SCHEMA,
    append_divergence_annotation,
    build_indexes,
    build_manifest,
    build_op_summaries,
    build_scenario_summaries,
    make_metadata,
    write_events_index,
    write_index_mapping,
    write_manifest,
    write_op_mapping,
    write_per_scenario_traces,
    write_scenario_mapping,
)
from .runtime_story import (  # noqa: F401
    build_runtime_story,
    story_to_coverage,
    story_to_runtime_signatures,
    write_runtime_story,
)
from .runtime_pipeline import (  # noqa: F401
    build_op_summary_from_index,
    generate_runtime_cut,
    load_events_from_index,
    promote_runtime_cut,
    run_from_expected_matrix,
)
from .derived_views import CalloutVsSyscallRow, callout_vs_syscall_comparison  # noqa: F401

__all__ = [
    "cli",
    "runtime_contract",
    "observations",
    "mapping_builders",
    "runtime_story",
    "derived_views",
    "runtime_pipeline",
    "harness_runner",
    "harness_generate",
    # observations
    "WORLD_ID",
    "RuntimeObservation",
    "derive_expectation_id",
    "make_scenario_id",
    "normalize_from_paths",
    "normalize_metadata_runner_results",
    "normalize_runtime_results",
    "serialize_observation",
    "write_metadata_runner_normalized_events",
    "write_normalized_events",
    # mapping builders
    "RUNTIME_LOG_SCHEMA",
    "RUNTIME_MAPPING_SCHEMA",
    "append_divergence_annotation",
    "build_indexes",
    "build_manifest",
    "build_op_summaries",
    "build_scenario_summaries",
    "make_metadata",
    "write_events_index",
    "write_index_mapping",
    "write_manifest",
    "write_op_mapping",
    "write_per_scenario_traces",
    "write_scenario_mapping",
    # runtime story
    "build_runtime_story",
    "story_to_coverage",
    "story_to_runtime_signatures",
    "write_runtime_story",
    # runtime pipeline
    "build_op_summary_from_index",
    "generate_runtime_cut",
    "load_events_from_index",
    "promote_runtime_cut",
    "run_from_expected_matrix",
    # derived views
    "CalloutVsSyscallRow",
    "callout_vs_syscall_comparison",
]
