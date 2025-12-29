"""
Harness adapters for runtime execution.

The harness is the "engine room" that actually runs probes. Keeping
it isolated helps ensure analysis code never mutates runtime state.
"""

from __future__ import annotations

from . import golden as golden  # noqa: F401
from . import runner as runner  # noqa: F401

# Keep harness exports explicit for tooling imports.
__all__ = ["golden", "runner"]
