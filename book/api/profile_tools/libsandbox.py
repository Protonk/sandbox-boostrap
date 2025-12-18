"""
Low-level bindings for libsandbox private compile interfaces (Sonoma baseline).

This module provides structural access to the SBPL compiler entry points that
produce compiled profile blobs (the modern graph-based format on this host).

It deliberately does **not** attempt to interpret kernel semantics. It is only
about turning SBPL inputs into compiled bytes and capturing byte-level metadata.

Parameter dictionaries:
  For this world, parameterized SBPL (via `(param "...")`) is compiled by
  constructing a libsandbox “params handle” with:

  - `sandbox_create_params()`
  - `sandbox_set_param(handle, key, value)`
  - `sandbox_free_params(handle)`

  and then passing the handle as the second argument to `sandbox_compile_*`.

  This is distinct from argv-style `KEY VALUE ... NULL` vectors used by higher
  level entry points such as `sandbox_init_with_parameters` / `sandbox-exec -D`.
  The compile-time params-handle interface is guarded (mapped-but-partial) by
  `structure:sbpl-parameterization` in
  `book/graph/concepts/validation/sbpl_parameterization_job.py`.
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


_LIBC = ctypes.CDLL(None)
_LIBC.free.argtypes = [ctypes.c_void_p]
_LIBC.free.restype = None


def free_error(err_ptr: Optional[ctypes.c_char_p]) -> None:
    if err_ptr and err_ptr.value:
        _LIBC.free(err_ptr)


def _configure_params_apis(lib: ctypes.CDLL) -> None:
    lib.sandbox_create_params.argtypes = []
    lib.sandbox_create_params.restype = ctypes.c_void_p
    lib.sandbox_set_param.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
    lib.sandbox_set_param.restype = ctypes.c_int
    lib.sandbox_free_params.argtypes = [ctypes.c_void_p]
    lib.sandbox_free_params.restype = None


def _configure_compile_apis(lib: ctypes.CDLL) -> None:
    # The second argument is treated as an opaque pointer (NULL or params handle).
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


def _build_params_handle(lib: ctypes.CDLL, params: Optional[ParamsInput]) -> Optional[ctypes.c_void_p]:
    if not params:
        return None
    if not hasattr(lib, "sandbox_create_params") or not hasattr(lib, "sandbox_set_param") or not hasattr(lib, "sandbox_free_params"):
        raise RuntimeError("libsandbox params API not available on this host (missing sandbox_create_params/set_param/free_params)")

    _configure_params_apis(lib)

    handle = ctypes.c_void_p(lib.sandbox_create_params())
    if not handle:
        raise RuntimeError("sandbox_create_params returned NULL")

    pairs: ParamPairs
    if isinstance(params, Mapping):
        pairs = list(params.items())
    else:
        pairs = list(params)

    for key, value in pairs:
        rv = int(lib.sandbox_set_param(handle, str(key).encode(), str(value).encode()))
        if rv != 0:
            lib.sandbox_free_params(handle)
            raise RuntimeError(f"sandbox_set_param({key!r}) failed with rv={rv}")

    return handle


def compile_string(lib: ctypes.CDLL, data: bytes, params: Optional[ParamsInput] = None) -> CompileTuple:
    _configure_compile_apis(lib)
    params_handle = _build_params_handle(lib, params)

    err = ctypes.c_char_p()
    try:
        prof = lib.sandbox_compile_string(data, params_handle, ctypes.byref(err))
        if not prof:
            detail = err.value.decode() if err.value else "unknown error"
            raise RuntimeError(f"compile failed: {detail}")

        blob = ctypes.string_at(prof.contents.bytecode, prof.contents.bytecode_length)
        profile_type = int(prof.contents.profile_type)
        length = int(prof.contents.bytecode_length)
        lib.sandbox_free_profile(prof)
        return blob, profile_type, length
    finally:
        free_error(err)
        if params_handle:
            _configure_params_apis(lib)
            lib.sandbox_free_params(params_handle)


def compile_file(lib: ctypes.CDLL, path: bytes, params: Optional[ParamsInput] = None) -> CompileTuple:
    _configure_compile_apis(lib)
    params_handle = _build_params_handle(lib, params)

    err = ctypes.c_char_p()
    try:
        prof = lib.sandbox_compile_file(path, params_handle, ctypes.byref(err))
        if not prof:
            detail = err.value.decode() if err.value else "unknown error"
            raise RuntimeError(f"compile failed: {detail}")

        blob = ctypes.string_at(prof.contents.bytecode, prof.contents.bytecode_length)
        profile_type = int(prof.contents.profile_type)
        length = int(prof.contents.bytecode_length)
        lib.sandbox_free_profile(prof)
        return blob, profile_type, length
    finally:
        free_error(err)
        if params_handle:
            _configure_params_apis(lib)
            lib.sandbox_free_params(params_handle)
