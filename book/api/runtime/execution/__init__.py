"""
Execution pipeline for runtime plan runs.

Includes channels, harness implementations, lane helpers, and the service
orchestrator that writes run-scoped bundles.

Keep execution and analysis separate. Execution is about producing
evidence; analysis is about interpreting it.
"""

from __future__ import annotations

# Submodules provide concrete runners, channels, and orchestration helpers.
