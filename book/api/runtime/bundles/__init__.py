"""
runtime artifact IO helpers.

This package exists to keep the runtime "bundle" contract enforceable:
- writers are responsible for atomic, deterministic artifact writes
- readers are responsible for strict integrity checks and safe fallbacks

The orchestration logic and bundle lifecycle live in `book.api.runtime.execution.service`.
"""

from __future__ import annotations

from .reader import (  # noqa: F401
    BundleState,
    resolve_bundle_dir,
    load_bundle_index_strict,
    open_bundle_unverified,
)
from .writer import (  # noqa: F401
    write_json_atomic,
    write_text_atomic,
    write_artifact_index,
)

__all__ = [
    "BundleState",
    "resolve_bundle_dir",
    "load_bundle_index_strict",
    "open_bundle_unverified",
    "write_json_atomic",
    "write_text_atomic",
    "write_artifact_index",
]
