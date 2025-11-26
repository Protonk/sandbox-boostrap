#!/usr/bin/env python3
"""
Compile sb/sample.sb into a binary sandbox blob using libsandbox.
Outputs build/sample.sb.bin for downstream decoding (e.g., sbdis, re2dot/resnarf).
"""

import ctypes
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.append(str(REPO_ROOT))

from concepts.cross import profile_ingestion as ingestion  # noqa: E402


class SandboxProfile(ctypes.Structure):
    _fields_ = [
        ("profile_type", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32),
        ("bytecode", ctypes.c_void_p),
        ("bytecode_length", ctypes.c_size_t),
    ]


def compile_profile(src: Path, out: Path):
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
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(blob)

    print(f"[+] compiled {src} -> {out}")
    print(f"    profile_type={profile.contents.profile_type} length={profile.contents.bytecode_length}")
    preview = blob[:32]
    grouped = ["".join(f"{b:02x}" for b in preview[i : i + 8]) for i in range(0, len(preview), 8)]
    print(f"    preview: {' '.join(grouped)}")

    # Parse header/sections via Axis 4.1 ingestion layer to avoid ad hoc parsing here.
    blob_wrapper = ingestion.ProfileBlob(bytes=blob, source="examples-sb")
    header = ingestion.parse_header(blob_wrapper)
    sections = ingestion.slice_sections(blob_wrapper, header)
    print(
        "    header: format={fmt} ops={ops} nodes={nodes} "
        "op_table_bytes={ot} node_bytes={nn} regex_literal_bytes={rl}".format(
            fmt=header.format_variant,
            ops=header.operation_count,
            nodes=header.node_count,
            ot=len(sections.op_table),
            nn=len(sections.nodes),
            rl=len(sections.regex_literals),
        )
    )

    lib.sandbox_free_profile(profile)
    if err:
        libc = ctypes.CDLL(None)
        libc.free(err)


if __name__ == "__main__":
    src = Path(__file__).parent / "sample.sb"
    out = Path(__file__).parent / "build" / "sample.sb.bin"
    compile_profile(src, out)
