"""
Low-level bindings for libsandbox private compile interfaces (Sonoma baseline).

This module provides structural access to the SBPL compiler entry points that
produce compiled profile blobs (the modern graph-based format on this host).

It deliberately does **not** attempt to interpret kernel semantics. It is only
about turning SBPL inputs into compiled bytes and capturing byte-level metadata.

Parameter vectors:
  Some userland entry points accept a classic `KEY VALUE ... NULL` argv-style
  parameter vector. This surface is treated as **under exploration**: callers
  should expect that some `(param "...")`-using profiles may still fail to
  compile depending on the exact API/shape required by libsandbox on this host.
"""

from __future__ import annotations

import ctypes
from typing import Mapping, Optional, Sequence, Tuple, Union

ParamPairs = Sequence[Tuple[str, str]]
ParamsInput = Union[Mapping[str, str], ParamPairs]
CompileTuple = Tuple[bytes, int, int]


class SandboxProfile(ctypes.Structure):
    _fields_ = [
        ("profile_type", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32),
        ("bytecode", ctypes.c_void_p),
        ("bytecode_length", ctypes.c_size_t),
    ]


def load_libsandbox() -> ctypes.CDLL:
    try:
        return ctypes.CDLL("libsandbox.dylib")
    except OSError as exc:
        raise RuntimeError(f"failed to load libsandbox.dylib: {exc}") from exc


def free_error(err_ptr: Optional[ctypes.c_char_p]) -> None:
    if err_ptr and err_ptr.value:
        ctypes.CDLL(None).free(err_ptr)


def build_param_vector(params: Optional[ParamsInput]) -> Tuple[Optional[ctypes.Array], Optional[ctypes.c_void_p]]:
    """
    Build an argv-style parameter vector: ["KEY1","VALUE1","KEY2","VALUE2",...,NULL].

    Returns (keepalive_array, void_ptr) so callers can keep the backing array
    alive across the foreign function call.
    """
    if not params:
        return None, None

    pairs: ParamPairs
    if isinstance(params, Mapping):
        pairs = list(params.items())
    else:
        pairs = list(params)

    flat: list[bytes] = []
    for key, value in pairs:
        flat.append(str(key).encode())
        flat.append(str(value).encode())

    arr_type = ctypes.c_char_p * (len(flat) + 1)
    arr = arr_type(*flat, None)
    ptr = ctypes.cast(arr, ctypes.c_void_p)
    return arr, ptr


def _configure_compile_apis(lib: ctypes.CDLL) -> None:
    # The second argument is treated as an opaque pointer (NULL or param vector),
    # matching the conventions used elsewhere in this repo’s probes.
    lib.sandbox_compile_string.argtypes = [
        ctypes.c_char_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_char_p),
    ]
    lib.sandbox_compile_string.restype = ctypes.POINTER(SandboxProfile)
    lib.sandbox_compile_file.argtypes = [
        ctypes.c_char_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_char_p),
    ]
    lib.sandbox_compile_file.restype = ctypes.POINTER(SandboxProfile)
    lib.sandbox_free_profile.argtypes = [ctypes.POINTER(SandboxProfile)]
    lib.sandbox_free_profile.restype = None


def compile_string(lib: ctypes.CDLL, data: bytes, params: Optional[ParamsInput] = None) -> CompileTuple:
    _configure_compile_apis(lib)
    keepalive, params_ptr = build_param_vector(params)
    _ = keepalive

    err = ctypes.c_char_p()
    prof = lib.sandbox_compile_string(data, params_ptr, ctypes.byref(err))
    if not prof:
        detail = err.value.decode() if err.value else "unknown error"
        free_error(err)
        raise RuntimeError(f"compile failed: {detail}")

    blob = ctypes.string_at(prof.contents.bytecode, prof.contents.bytecode_length)
    profile_type = int(prof.contents.profile_type)
    length = int(prof.contents.bytecode_length)
    lib.sandbox_free_profile(prof)
    free_error(err)
    return blob, profile_type, length


def compile_file(lib: ctypes.CDLL, path: bytes, params: Optional[ParamsInput] = None) -> CompileTuple:
    _configure_compile_apis(lib)
    keepalive, params_ptr = build_param_vector(params)
    _ = keepalive

    err = ctypes.c_char_p()
    prof = lib.sandbox_compile_file(path, params_ptr, ctypes.byref(err))
    if not prof:
        detail = err.value.decode() if err.value else "unknown error"
        free_error(err)
        raise RuntimeError(f"compile failed: {detail}")

    blob = ctypes.string_at(prof.contents.bytecode, prof.contents.bytecode_length)
    profile_type = int(prof.contents.profile_type)
    length = int(prof.contents.bytecode_length)
    lib.sandbox_free_profile(prof)
    free_error(err)
    return blob, profile_type, length
