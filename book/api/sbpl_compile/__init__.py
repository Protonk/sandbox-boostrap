"""
Shim over `book.api.profile_tools.compile`.

This module is kept for backward compatibility; prefer importing from
`book.api.profile_tools`.
"""

from __future__ import annotations

import warnings
from pathlib import Path
from typing import Optional

from book.api.profile_tools import compile as compile_mod
from book.api.profile_tools import CompileResult, compile_sbpl_file, compile_sbpl_string, default_output_for, hex_preview


def _warn() -> None:
    warnings.warn(
        "book.api.sbpl_compile is deprecated; use book.api.profile_tools (compile submodule)",
        DeprecationWarning,
        stacklevel=2,
    )


def compile_sbpl_string(text: str, lib: Optional[object] = None, *, params: Optional[object] = None) -> CompileResult:
    _warn()
    return compile_mod.compile_sbpl_string(text, lib=lib, params=params)  # type: ignore[arg-type]


def compile_sbpl_file(
    src: Path,
    dst: Optional[Path] = None,
    lib: Optional[object] = None,
    *,
    params: Optional[object] = None,
) -> CompileResult:
    _warn()
    return compile_mod.compile_sbpl_file(src, dst=dst, lib=lib, params=params)  # type: ignore[arg-type]


def hex_preview(blob: bytes, count: int = 32) -> str:
    _warn()
    return compile_mod.hex_preview(blob, count=count)


def default_output_for(path: Path) -> Path:
    _warn()
    return compile_mod.default_output_for(path)
