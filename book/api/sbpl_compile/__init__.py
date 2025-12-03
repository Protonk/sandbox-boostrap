"""
Helpers to compile SBPL into binary sandbox profile blobs via libsandbox.

Scope:
- macOS Sonoma 14.4.1 on Apple Silicon with SIP enabled.
- Uses the private `sandbox_compile_*` entry points exposed by
  `libsandbox.dylib` to produce the modern graph-based binary format
  described in substrate/Appendix.md.

Exports:
- `compile_sbpl_file(Path, Path)` → writes blob to disk and returns metadata.
- `compile_sbpl_string(str)` → returns (blob, metadata) without touching disk.
- `hex_preview(bytes, count=32)` → small hex render for logs.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple


class SandboxProfile(ctypes.Structure):
    _fields_ = [
        ("profile_type", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32),
        ("bytecode", ctypes.c_void_p),
        ("bytecode_length", ctypes.c_size_t),
    ]


@dataclass
class CompileResult:
    blob: bytes
    profile_type: int
    length: int


def _load_libsandbox() -> ctypes.CDLL:
    try:
        return ctypes.CDLL("libsandbox.dylib")
    except OSError as exc:
        raise RuntimeError(f"failed to load libsandbox.dylib: {exc}") from exc


def _free_error(err_ptr: Optional[ctypes.c_char_p]) -> None:
    if err_ptr and err_ptr.value:
        ctypes.CDLL(None).free(err_ptr)


def _compile_bytes(lib: ctypes.CDLL, data: bytes) -> CompileResult:
    lib.sandbox_compile_string.argtypes = [
        ctypes.c_char_p,
        ctypes.c_uint64,
        ctypes.POINTER(ctypes.c_char_p),
    ]
    lib.sandbox_compile_string.restype = ctypes.POINTER(SandboxProfile)
    lib.sandbox_free_profile.argtypes = [ctypes.POINTER(SandboxProfile)]
    lib.sandbox_free_profile.restype = None

    err = ctypes.c_char_p()
    prof = lib.sandbox_compile_string(data, 0, ctypes.byref(err))
    if not prof:
        detail = err.value.decode() if err.value else "unknown error"
        _free_error(err)
        raise RuntimeError(f"compile failed: {detail}")

    blob = ctypes.string_at(prof.contents.bytecode, prof.contents.bytecode_length)
    result = CompileResult(
        blob=blob,
        profile_type=int(prof.contents.profile_type),
        length=int(prof.contents.bytecode_length),
    )
    lib.sandbox_free_profile(prof)
    _free_error(err)
    return result


def compile_sbpl_string(text: str, lib: Optional[ctypes.CDLL] = None) -> CompileResult:
    """Compile SBPL source text into a compiled blob."""
    lib = lib or _load_libsandbox()
    return _compile_bytes(lib, text.encode())


def compile_sbpl_file(src: Path, dst: Optional[Path] = None, lib: Optional[ctypes.CDLL] = None) -> CompileResult:
    """
    Compile an SBPL file. If dst is provided, writes the compiled blob there.
    Returns CompileResult with blob bytes and metadata.
    """
    lib = lib or _load_libsandbox()
    text = src.read_text().encode()
    result = _compile_bytes(lib, text)
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
