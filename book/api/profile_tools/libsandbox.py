"""
Compatibility shim for the libsandbox compile bindings.

New code should prefer `book.api.profile_tools.compile.libsandbox`.
"""

from __future__ import annotations

from .compile.libsandbox import *  # noqa: F403

