#!/usr/bin/env python3
"""
Compile an SBPL file into a binary sandbox profile blob using libsandbox.

Usage:
  sbsnarf.py input.sb output.sb.bin
"""

import ctypes
import sys
from pathlib import Path


class SandboxProfile(ctypes.Structure):
    _fields_ = [
        ("profile_type", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32),
        ("bytecode", ctypes.c_void_p),
        ("bytecode_length", ctypes.c_size_t),
    ]


def compile_sbpl(src: Path, dst: Path):
    lib = ctypes.CDLL("libsandbox.dylib")
    lib.sandbox_compile_file.argtypes = [
        ctypes.c_char_p,
        ctypes.c_uint64,
        ctypes.POINTER(ctypes.c_char_p),
    ]
    lib.sandbox_compile_file.restype = ctypes.POINTER(SandboxProfile)
    lib.sandbox_free_profile.argtypes = [ctypes.POINTER(SandboxProfile)]
    lib.sandbox_free_profile.restype = None

    err = ctypes.c_char_p()
    profile = lib.sandbox_compile_file(str(src).encode(), 0, ctypes.byref(err))
    if not profile:
        detail = err.value.decode() if err.value else "unknown error"
        raise SystemExit(f"compile failed: {detail}")

    blob = ctypes.string_at(profile.contents.bytecode, profile.contents.bytecode_length)
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(blob)
    print(f"[+] compiled {src} -> {dst} (len={profile.contents.bytecode_length}, type={profile.contents.profile_type})")

    lib.sandbox_free_profile(profile)
    if err:
        ctypes.CDLL(None).free(err)


def main():
    if len(sys.argv) != 3:
        print("usage: sbsnarf.py input.sb output.sb.bin")
        sys.exit(1)

    compile_sbpl(Path(sys.argv[1]), Path(sys.argv[2]))


if __name__ == "__main__":
    main()
