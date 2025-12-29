"""
SBPL compilation helpers (Sonoma baseline).

These wrap the private libsandbox entry points to produce compiled
graph-based sandbox blobs. Exposed via `book.api.profile`.

This module is a *compile-stage* wrapper only:
- It produces compiled bytes (`.sb.bin`) from SBPL source.
- It does not apply or execute profiles (no `sandbox_init` / `sandbox_apply`).
  Runtime execution lives under `book/api/runtime/`.

If you need lower-level control (ctypes handles, params API), see:
- `book/api/profile/compile/libsandbox.py`
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from . import libsandbox


@dataclass
class CompileResult:
    """
    Result of compiling an SBPL input to a compiled blob.

    `profile_type` and `length` come from libsandbox's `sandbox_profile` struct.
    Callers should treat these as *structural* metadata: they help correlate
    compiler behavior across inputs on this world baseline, but they do not
    directly imply policy semantics.
    """

    blob: bytes
    profile_type: int
    length: int


def compile_sbpl_string(
    text: str,
    lib: Optional[object] = None,
    *,
    params: Optional[libsandbox.ParamsInput] = None,
) -> CompileResult:
    """
    Compile SBPL source text into a compiled blob.

    Args:
        text: SBPL source text (TinyScheme syntax).
        lib: Optional preloaded `ctypes.CDLL` for libsandbox.
        params: Optional compile-time `(param "...")` values. This uses the
            libsandbox params-handle interface (not apply-time argv params).

    Returns:
        `CompileResult` containing the compiled blob bytes and minimal metadata.
    """
    lib = lib or libsandbox.load_libsandbox()
    blob, profile_type, length = libsandbox.compile_string(lib, text.encode(), params=params)
    return CompileResult(blob=blob, profile_type=profile_type, length=length)


def compile_sbpl_file(
    src: Path,
    dst: Optional[Path] = None,
    lib: Optional[object] = None,
    *,
    params: Optional[libsandbox.ParamsInput] = None,
) -> CompileResult:
    """
    Compile an SBPL file. If dst is provided, writes the compiled blob there.
    Returns CompileResult with blob bytes and metadata.
    """
    lib = lib or libsandbox.load_libsandbox()
    # libsandbox resolves `sandbox_compile_file` paths relative to its own search
    # roots; passing an absolute path is the most reliable way to compile a repo
    # SBPL file on this host.
    # Pass an absolute path so libsandbox doesn't interpret the input relative
    # to its internal search roots (which can surprise when running from
    # different working directories).
    src_abs = src.resolve()
    blob, profile_type, length = libsandbox.compile_file(lib, str(src_abs).encode(), params=params)
    result = CompileResult(blob=blob, profile_type=profile_type, length=length)
    if dst:
        # Keep the CLI behavior consistent: create parents and write atomically
        # from the in-memory blob (we already have it).
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(result.blob)
    return result


def hex_preview(blob: bytes, count: int = 32) -> str:
    """
    Render the first few bytes of the compiled blob for logging.

    This is a debugging helper: it is useful when visually comparing compiler
    output across small SBPL variations.
    """
    preview = blob[:count]
    grouped = ["".join(f"{b:02x}" for b in preview[i : i + 8]) for i in range(0, len(preview), 8)]
    return " ".join(grouped)


def default_output_for(path: Path) -> Path:
    """
    Choose an output path next to the input with a `.sb.bin` suffix.

    Rules:
    - For `foo.sb`, return `foo.sb.bin` (replace suffix).
    - For non-`.sb` paths (e.g. `foo.txt`), return `foo.txt.sb.bin` (append).
    """
    suffix = ".sb.bin" if not path.name.endswith(".sb") else ".bin"
    return path.with_name(f"{path.name}{suffix}") if suffix == ".sb.bin" else path.with_suffix(".sb.bin")
