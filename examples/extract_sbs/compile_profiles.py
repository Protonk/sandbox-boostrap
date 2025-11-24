#!/usr/bin/env python3
"""
Compile selected SBPL profiles into binary sandbox blobs using libsandbox.

This is a modern replacement for the old kernelcache offset scraper. It
demonstrates Orientation.md §3.2 (SBPL → TinyScheme → compiled graph) by
invoking the private `sandbox_compile_file` API exposed by libsandbox.dylib on
macOS 14.x. The resulting bytecode matches the binary profile layout described
in Appendix.md (“Binary Profile Formats and Policy Graphs”): header + operation
pointers + node array + literal/regex tables.
"""

import argparse
import ctypes
from pathlib import Path


class SandboxProfile(ctypes.Structure):
    _fields_ = [
        ("profile_type", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32),
        ("bytecode", ctypes.c_void_p),
        ("bytecode_length", ctypes.c_size_t),
    ]


def _load_libsandbox():
    try:
        return ctypes.CDLL("libsandbox.dylib")
    except OSError as exc:
        raise SystemExit(f"failed to load libsandbox.dylib: {exc}") from exc


def compile_profile(lib, path: Path) -> bytes:
    """Compile an SBPL file and return the compiled bytecode blob."""
    lib.sandbox_compile_file.argtypes = [
        ctypes.c_char_p,
        ctypes.c_uint64,
        ctypes.POINTER(ctypes.c_char_p),
    ]
    lib.sandbox_compile_file.restype = ctypes.POINTER(SandboxProfile)
    lib.sandbox_free_profile.argtypes = [ctypes.POINTER(SandboxProfile)]
    lib.sandbox_free_profile.restype = None

    err = ctypes.c_char_p()
    profile = lib.sandbox_compile_file(str(path).encode(), 0, ctypes.byref(err))
    if not profile:
        detail = err.value.decode() if err.value else "unknown error"
        if err:
            ctypes.CDLL(None).free(err)
        raise SystemExit(f"compile failed for {path}: {detail}")

    bc_len = profile.contents.bytecode_length
    bc_ptr = profile.contents.bytecode
    blob = ctypes.string_at(bc_ptr, bc_len)
    lib.sandbox_free_profile(profile)
    if err:
        libc = ctypes.CDLL(None)
        libc.free(err)
    return blob


def hex_preview(blob: bytes, count: int = 32) -> str:
    """Render a short preview of the compiled profile bytes."""
    preview = blob[:count]
    grouped = ["".join(f"{b:02x}" for b in preview[i : i + 8]) for i in range(0, len(preview), 8)]
    return " ".join(grouped)


def main():
    default_profiles = ["airlock.sb", "bsd.sb"]
    parser = argparse.ArgumentParser(
        description="Compile SBPL profiles to binary blobs using libsandbox (macOS 14.x)."
    )
    parser.add_argument(
        "--profiles-dir",
        type=Path,
        default=Path("/System/Library/Sandbox/Profiles"),
        help="Directory containing .sb files (default: system profiles).",
    )
    parser.add_argument(
        "--names",
        nargs="+",
        default=default_profiles,
        help="Profile filenames to compile (default: %(default)s).",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("build/profiles"),
        help="Where to write .sb.bin outputs (created if missing).",
    )
    args = parser.parse_args()

    lib = _load_libsandbox()
    args.out_dir.mkdir(parents=True, exist_ok=True)

    for name in args.names:
        sb_path = args.profiles_dir / name
        if not sb_path.exists():
            print(f"[skip] {sb_path} (not found)")
            continue

        print(f"[+] compiling {sb_path}")
        blob = compile_profile(lib, sb_path)

        out_path = args.out_dir / f"{name}.bin"
        out_path.write_bytes(blob)
        print(f"    wrote {out_path} ({len(blob)} bytes)")
        print(f"    preview: {hex_preview(blob)}")


if __name__ == "__main__":
    main()
