"""
Plan and registry helpers for runtime execution.

Plan data makes runtime execution reproducible because the probes and
profiles are declared as JSON, not encoded in experiment code.
"""

from __future__ import annotations

# The concrete plan/registry helpers live in submodules; keep this package light.
