"""
Shim over `book.api.profile_tools.inspect`.

Kept for backward compatibility; prefer importing from
`book.api.profile_tools`.
"""

from __future__ import annotations

import warnings
from typing import Sequence

from book.api.profile_tools import inspect as _profile_inspect
from book.api.profile_tools.inspect import Summary as InspectSummary


def _warn() -> None:
    warnings.warn(
        "book.api.inspect_profile is deprecated; use book.api.profile_tools (inspect submodule)",
        DeprecationWarning,
        stacklevel=2,
    )


def summarize_blob(blob: bytes, strides: Sequence[int] = (8, 12, 16)) -> InspectSummary:
    _warn()
    return _profile_inspect.summarize_blob(blob, strides=strides)  # type: ignore[no-any-return]


def load_blob(path):
    _warn()
    return _profile_inspect.load_blob(path)


__all__ = ["InspectSummary", "load_blob", "summarize_blob"]
