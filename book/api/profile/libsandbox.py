"""
Compatibility import for libsandbox compile bindings.

Why this exists:
- Historically, some scripts imported `book.api.profile.libsandbox` to reach the
  `sandbox_compile_*` ctypes bindings.
- The canonical location for these bindings is now
  `book.api.profile.compile.libsandbox`.

What this is (and is not):
- This module only re-exports compile-related symbols (compile + params-handle).
- It is not a general-purpose wrapper around every libsandbox entry point.
- Prefer importing from `book.api.profile.compile.libsandbox` in new code so the
  module boundary stays clear.
"""

from __future__ import annotations

# Re-export for convenience / historical imports.
# We keep a star import here because the underlying module is the authoritative
# list of supported ctypes bindings, and this file intentionally does not add
# behavior.
from .compile.libsandbox import *  # noqa: F403
