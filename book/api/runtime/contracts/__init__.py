"""
Runtime contract surface (schemas + normalization helpers).

This package gathers the schema and normalization helpers that keep runtime
evidence stable across tools and experiments.

Having a single contract layer makes it harder to accidentally
reinterpret stderr strings as evidence, which is a common pitfall in sandbox
analysis.
"""

from __future__ import annotations

from . import schema as schema  # noqa: F401
from . import models as models  # noqa: F401
from . import normalize as normalize  # noqa: F401

from .models import (  # noqa: F401
    WORLD_ID,
    GoldenArtifacts,
    RuntimeCut,
    RuntimeObservation,
    RuntimeRun,
)

# Re-export core models for concise contract imports.
__all__ = [
    "schema",
    "models",
    "normalize",
    "WORLD_ID",
    "GoldenArtifacts",
    "RuntimeCut",
    "RuntimeObservation",
    "RuntimeRun",
]
