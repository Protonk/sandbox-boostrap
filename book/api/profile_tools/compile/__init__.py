"""
SBPL compilation helpers (Sonoma baseline).

Public API:
- `compile_sbpl_file`, `compile_sbpl_string`
- `CompileResult`, `hex_preview`

Low-level bindings live in `book.api.profile_tools.compile.libsandbox`.
"""

from __future__ import annotations

from .api import CompileResult, compile_sbpl_file, compile_sbpl_string, default_output_for, hex_preview  # noqa: F401
from .libsandbox import ParamPairs, ParamsInput  # noqa: F401

__all__ = [
    "CompileResult",
    "ParamsInput",
    "ParamPairs",
    "compile_sbpl_file",
    "compile_sbpl_string",
    "hex_preview",
    "default_output_for",
]

