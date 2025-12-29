"""
Shared low-level helpers for `book.api.profile_tools`.

This package is internal: it exists to avoid circular imports and duplication
across the profile tooling surfaces.
"""

from __future__ import annotations

from . import bytes_util as bytes_util  # noqa: F401

__all__ = ["bytes_util"]

