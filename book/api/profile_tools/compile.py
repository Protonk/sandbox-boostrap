"""
SBPL compilation helpers (Sonoma baseline).

These wrap the private libsandbox entry points to produce compiled
graph-based sandbox blobs. Exposed via `profile_tools` and shims in
`sbpl_compile`.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from . import libsandbox


@dataclass
class CompileResult:
    blob: bytes
    profile_type: int
    length: int


def compile_sbpl_string(
    text: str,
    lib: Optional[object] = None,
    *,
    params: Optional[libsandbox.ParamsInput] = None,
) -> CompileResult:
    """Compile SBPL source text into a compiled blob."""
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
    src_abs = src.resolve()
    blob, profile_type, length = libsandbox.compile_file(lib, str(src_abs).encode(), params=params)
    result = CompileResult(blob=blob, profile_type=profile_type, length=length)
    if dst:
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(result.blob)
    return result


def hex_preview(blob: bytes, count: int = 32) -> str:
    """Render the first few bytes of the compiled blob for logging."""
    preview = blob[:count]
    grouped = ["".join(f"{b:02x}" for b in preview[i : i + 8]) for i in range(0, len(preview), 8)]
    return " ".join(grouped)


def default_output_for(path: Path) -> Path:
    """Helper to choose an output path next to the input with .sb.bin suffix."""
    suffix = ".sb.bin" if not path.name.endswith(".sb") else ".bin"
    return path.with_name(f"{path.name}{suffix}") if suffix == ".sb.bin" else path.with_suffix(".sb.bin")
