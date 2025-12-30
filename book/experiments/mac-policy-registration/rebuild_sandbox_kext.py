"""
Rebuild the sandbox kext Mach-O from the Boot Kernel Collection fileset entry.

Why this exists:
- The carved `sandbox_kext.bin` under `book/dumps/ghidra/private/aapl-restricted/<build>/kernel/` was
  a thin slice between adjacent LC_FILESET_ENTRY offsets and omits the __DATA,
  __DATA_CONST, and __LINKEDIT ranges. Ghidra import fails with out-of-bounds
  errors as a result.
- This helper locates the `com.apple.security.sandbox` fileset entry in the
  BootKernelCollection, extracts the full byte range covering all segments
  (including LINKEDIT), and rewrites load-command file offsets so they are
  relative to the rebuilt file (base = min segment fileoff).

Outputs:
- For a single entry: writes `book/dumps/ghidra/private/aapl-restricted/<build>/kernel/sandbox_kext.bin`
  (for the default `com.apple.security.sandbox`) or `sandbox_kext_<entry>.bin`
  for other entry IDs.
- With `--all-matching`, rebuilds every LC_FILESET_ENTRY whose name contains
  sandbox/seatbelt substrings into separate `sandbox_kext_<entry>.bin` files.

Usage:
    python book/experiments/mac-policy-registration/rebuild_sandbox_kext.py \
        --build-id 14.4.1-23E224
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

from book.api import path_utils
from book.api.ghidra import scaffold

LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xB
LC_FILESET_ENTRY = 0x35
LC_FILESET_ENTRY_REQ = 0x80000035
# All share the same layout: cmd, cmdsize, dataoff, datasize.
LINKEDIT_DATA_CMDS = {0x1D, 0x1E, 0x2F, 0x31, 0x34}


def _read_header(data: bytes, offset: int = 0) -> Tuple[int, int, int]:
    magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack_from(
        "<IiiIIIII", data, offset
    )
    if magic != 0xFEEDFACF:
        raise ValueError(f"Unexpected magic at {offset:#x}: {magic:#x}")
    return ncmds, sizeofcmds, filetype


def _find_fileset_entry(kc_path: Path, entry_id: str) -> int:
    for name, fileoff in _iter_fileset_entries(kc_path).items():
        if name == entry_id:
            return fileoff
    raise ValueError(f"Entry {entry_id} not found in {kc_path}")


def _iter_fileset_entries(kc_path: Path) -> Dict[str, int]:
    """Return mapping of LC_FILESET_ENTRY name -> file offset."""
    with kc_path.open("rb") as f:
        header = f.read(32)
        ncmds, sizeofcmds, _ = _read_header(header)
        f.seek(0)
        cmd_bytes = f.read(32 + sizeofcmds)

    entries: Dict[str, int] = {}
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", cmd_bytes, off)
        if cmd in (LC_FILESET_ENTRY, LC_FILESET_ENTRY_REQ):
            vmaddr, fileoff, entry_off, reserved = struct.unpack_from("<QQII", cmd_bytes, off + 8)
            str_start = off + entry_off
            str_bytes = cmd_bytes[str_start : off + cmdsize].split(b"\x00", 1)[0]
            name = str_bytes.decode("ascii", errors="ignore")
            entries[name] = fileoff
        off += cmdsize
    return entries


def _compute_bounds(entry_blob: bytes) -> Tuple[int, int, int]:
    """Return (base, max_end, ncmds) using absolute file offsets from the header."""
    ncmds, sizeofcmds, filetype = _read_header(entry_blob, 0)
    off = 32
    base = None
    max_end = 0
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", entry_blob, off)
        if cmd == LC_SEGMENT_64:
            segname, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags = struct.unpack_from(
                "<16sQQQQIIII", entry_blob, off + 8
            )
            if fileoff and (base is None or fileoff < base):
                base = fileoff
            max_end = max(max_end, fileoff + filesize)
            sect_off = off + 72
            for _ in range(nsects):
                sect = struct.unpack_from("<16s16sQQIIIIIII", entry_blob, sect_off)
                offset = sect[4]
                size = sect[3]
                max_end = max(max_end, offset + size)
                sect_off += 80
        elif cmd == LC_SYMTAB:
            symoff, nsyms, stroff, strsize = struct.unpack_from("<IIII", entry_blob, off + 8)
            max_end = max(max_end, symoff + strsize)
        elif cmd == LC_DYSYMTAB:
            (
                ilocalsym,
                nlocalsym,
                iextdefsym,
                nextdefsym,
                iundefsym,
                nundefsym,
                tocoff,
                ntoc,
                modtaboff,
                nmodtab,
                extrefsymoff,
                nextrefsyms,
                indirectsymoff,
                nindirectsyms,
                extreloff,
                nextrel,
                locreloff,
                nlocrel,
            ) = struct.unpack_from("<IIIIIIIIIIIIIIIIII", entry_blob, off + 8)
            for val, size in [
                (tocoff, ntoc * 0x10),
                (modtaboff, nmodtab * 0x38),
                (extrefsymoff, nextrefsyms * 4),
                (indirectsymoff, nindirectsyms * 4),
                (extreloff, nextrel * 8),
                (locreloff, nlocrel * 8),
            ]:
                if val:
                    max_end = max(max_end, val + size)
        elif cmd in LINKEDIT_DATA_CMDS:
            dataoff, datasize = struct.unpack_from("<II", entry_blob, off + 8)
            max_end = max(max_end, dataoff + datasize)
        off += cmdsize
    if base is None:
        raise ValueError("No segment fileoff found in entry")
    return base, max_end, ncmds


def _adjust_offsets(buf: bytearray, hdr_offset: int, base: int, ncmds: int) -> None:
    """Rewrite file offsets to be relative to `base` inside the provided buffer."""
    off = hdr_offset + 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", buf, off)
        if cmd == LC_SEGMENT_64:
            seg_fields = list(struct.unpack_from("<16sQQQQIIII", buf, off + 8))
            fileoff = seg_fields[3]
            if fileoff:
                seg_fields[3] = fileoff - base
            struct.pack_into("<16sQQQQIIII", buf, off + 8, *seg_fields)
            nsects = seg_fields[7]
            sect_off = off + 72
            for _ in range(nsects):
                sect_fields = list(struct.unpack_from("<16s16sQQIIIIIII", buf, sect_off))
                if sect_fields[4]:
                    sect_fields[4] = sect_fields[4] - base
                if sect_fields[6]:
                    sect_fields[6] = max(0, sect_fields[6] - base)
                struct.pack_into("<16s16sQQIIIIIII", buf, sect_off, *sect_fields)
                sect_off += 80
        elif cmd == LC_SYMTAB:
            symoff, nsyms, stroff, strsize = struct.unpack_from("<IIII", buf, off + 8)
            new_symoff = symoff - base if symoff else 0
            new_stroff = stroff - base if stroff else 0
            struct.pack_into("<IIII", buf, off + 8, new_symoff, nsyms, new_stroff, strsize)
        elif cmd == LC_DYSYMTAB:
            fields = list(struct.unpack_from("<IIIIIIIIIIIIIIIIII", buf, off + 8))
            # Offsets at positions 6, 8, 10, 12, 14, 16.
            for idx in (6, 8, 10, 12, 14, 16):
                if fields[idx]:
                    fields[idx] = fields[idx] - base
            struct.pack_into("<IIIIIIIIIIIIIIIIII", buf, off + 8, *fields)
        elif cmd in LINKEDIT_DATA_CMDS:
            dataoff, datasize = struct.unpack_from("<II", buf, off + 8)
            new_off = dataoff - base if dataoff else 0
            struct.pack_into("<II", buf, off + 8, new_off, datasize)
        off += cmdsize


def _sanitize_name(name: str) -> str:
    return name.replace("/", "_").replace(".", "_").replace(":", "_")


def rebuild(build_id: str, entry_id: str = "com.apple.security.sandbox", dest_name: str | None = None) -> Path:
    repo_root = path_utils.find_repo_root()
    kc_path = path_utils.ensure_absolute(repo_root / f"book/dumps/ghidra/private/aapl-restricted/{build_id}/kernel/BootKernelCollection.kc")
    base_dir = path_utils.ensure_absolute(repo_root / f"book/dumps/ghidra/private/aapl-restricted/{build_id}/kernel")
    if dest_name:
        dest_path = base_dir / dest_name
    elif entry_id == "com.apple.security.sandbox":
        dest_path = base_dir / "sandbox_kext.bin"
    else:
        dest_path = base_dir / f"sandbox_kext_{_sanitize_name(entry_id)}.bin"

    entry_off = _find_fileset_entry(kc_path, entry_id)

    with kc_path.open("rb") as f:
        f.seek(entry_off)
        header = f.read(32)
        ncmds, sizeofcmds, _ = _read_header(header, 0)
        f.seek(entry_off)
        entry_cmds = f.read(32 + sizeofcmds)

    base, max_end, _ = _compute_bounds(entry_cmds)
    span = max_end - base

    with kc_path.open("rb") as f:
        f.seek(base)
        chunk = bytearray(f.read(span))

    hdr_offset = entry_off - base
    _adjust_offsets(chunk, hdr_offset, base, ncmds)

    dest_path.parent.mkdir(parents=True, exist_ok=True)
    dest_path.write_bytes(chunk)
    return dest_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Rebuild sandbox kext Mach-O with fixed file offsets.")
    parser.add_argument("--build-id", default=scaffold.DEFAULT_BUILD_ID, help="aapl-restricted build ID")
    parser.add_argument("--entry-id", default="com.apple.security.sandbox", help="LC_FILESET_ENTRY id to rebuild")
    parser.add_argument(
        "--all-matching",
        action="store_true",
        help="Rebuild all LC_FILESET_ENTRY names containing 'sandbox' or 'seatbelt' (case-insensitive).",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List LC_FILESET_ENTRY names and exit.",
    )
    args = parser.parse_args()

    if args.list:
        repo_root = path_utils.find_repo_root()
        kc_path = path_utils.ensure_absolute(repo_root / f"book/dumps/ghidra/private/aapl-restricted/{args.build_id}/kernel/BootKernelCollection.kc")
        entries = _iter_fileset_entries(kc_path)
        for name, off in entries.items():
            print(f"{name}\t0x{off:x}")
        return 0

    if args.all_matching:
        keywords = ("sandbox", "seatbelt")
        repo_root = path_utils.find_repo_root()
        kc_path = path_utils.ensure_absolute(repo_root / f"book/dumps/ghidra/private/aapl-restricted/{args.build_id}/kernel/BootKernelCollection.kc")
        entries = _iter_fileset_entries(kc_path)
        matches = [name for name in entries if any(k in name.lower() for k in keywords)]
        if not matches:
            print("No sandbox/seatbelt fileset entries found")
            return 1
        for name in matches:
            dest_name = f"sandbox_kext_{_sanitize_name(name)}.bin"
            out_path = rebuild(args.build_id, name, dest_name=dest_name)
            print(f"Rebuilt {name} -> {out_path}")
        # Ensure canonical sandbox_kext.bin exists for the default entry if present.
        if "com.apple.security.sandbox" in entries:
            rebuild(args.build_id, "com.apple.security.sandbox")
        return 0
    else:
        out_path = rebuild(args.build_id, args.entry_id)
        print(f"Rebuilt {args.entry_id} for build {args.build_id}: {out_path}")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
