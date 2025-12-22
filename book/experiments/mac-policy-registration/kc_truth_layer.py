#!/usr/bin/env python3
"""
Build a KC "truth layer" by enumerating fileset entries and decoding chained fixups.

Outputs (default under book/experiments/mac-policy-registration/out):
- kc_fileset_index.json
- kc_fixups_summary.json
- kc_fixups.jsonl (one fixup record per line)

Notes:
- Fixup decoding for pointer_format=8 is heuristic and should be treated as
  partial/under exploration until validated against additional witnesses.
"""

from __future__ import annotations

import argparse
import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from book.api import path_utils

MH_MAGIC_64 = 0xFEEDFACF
MH_FILESET = 0xC
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xB
LC_FILESET_ENTRY = 0x35
LC_FILESET_ENTRY_REQ = 0x80000035
LC_DYLD_CHAINED_FIXUPS = 0x80000034
LINKEDIT_DATA_CMDS = {0x1D, 0x1E, 0x2F, 0x31, 0x34}


@dataclass
class MachHeader:
    ncmds: int
    sizeofcmds: int
    filetype: int


@dataclass
class Segment:
    name: str
    vmaddr: int
    vmsize: int
    fileoff: int
    filesize: int


def _read_header(buf: bytes, offset: int = 0) -> MachHeader:
    magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack_from(
        "<IiiIIIII", buf, offset
    )
    if magic != MH_MAGIC_64:
        raise ValueError(f"Unexpected Mach-O magic {magic:#x} at {offset:#x}")
    return MachHeader(ncmds=ncmds, sizeofcmds=sizeofcmds, filetype=filetype)


def _load_cmd_bytes(path: Path, offset: int) -> Tuple[MachHeader, bytes]:
    with path.open("rb") as f:
        f.seek(offset)
        hdr = f.read(32)
        header = _read_header(hdr, 0)
        f.seek(offset)
        cmds = f.read(32 + header.sizeofcmds)
    return header, cmds


def _iter_load_commands(cmds: bytes, ncmds: int) -> Iterable[Tuple[int, int, int]]:
    off = 32
    for _ in range(ncmds):
        if off + 8 > len(cmds):
            break
        cmd, cmdsize = struct.unpack_from("<II", cmds, off)
        yield cmd, cmdsize, off
        off += cmdsize


def _parse_segments(cmds: bytes, ncmds: int) -> List[Segment]:
    segments: List[Segment] = []
    for cmd, cmdsize, off in _iter_load_commands(cmds, ncmds):
        if cmd != LC_SEGMENT_64:
            continue
        segname = cmds[off + 8 : off + 24].split(b"\x00", 1)[0].decode("ascii", errors="ignore")
        vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags = struct.unpack_from(
            "<QQQQIIII", cmds, off + 24
        )
        segments.append(
            Segment(name=segname, vmaddr=vmaddr, vmsize=vmsize, fileoff=fileoff, filesize=filesize)
        )
    return segments


def _parse_fileset_entries(cmds: bytes, ncmds: int) -> List[Dict[str, int | str]]:
    entries: List[Dict[str, int | str]] = []
    for cmd, cmdsize, off in _iter_load_commands(cmds, ncmds):
        if cmd not in (LC_FILESET_ENTRY, LC_FILESET_ENTRY_REQ):
            continue
        vmaddr, fileoff, entry_off, reserved = struct.unpack_from("<QQII", cmds, off + 8)
        str_start = off + entry_off
        str_bytes = cmds[str_start : off + cmdsize].split(b"\x00", 1)[0]
        name = str_bytes.decode("ascii", errors="ignore")
        entries.append(
            {
                "entry_id": name,
                "vmaddr": vmaddr,
                "fileoff": fileoff,
                "cmdsize": cmdsize,
            }
        )
    return entries


def _compute_entry_bounds(cmds: bytes, ncmds: int) -> Tuple[int, int, int, int, List[str]]:
    """Return (file_base, file_end, vm_base, vm_end, segment_names)."""
    file_base: Optional[int] = None
    file_end = 0
    vm_base: Optional[int] = None
    vm_end = 0
    segment_names: List[str] = []

    for cmd, cmdsize, off in _iter_load_commands(cmds, ncmds):
        if cmd == LC_SEGMENT_64:
            segname, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags = struct.unpack_from(
                "<16sQQQQIIII", cmds, off + 8
            )
            segname = segname.split(b"\x00", 1)[0].decode("ascii", errors="ignore")
            segment_names.append(segname)
            if fileoff and (file_base is None or fileoff < file_base):
                file_base = fileoff
            file_end = max(file_end, fileoff + filesize)
            vm_base = vmaddr if vm_base is None else min(vm_base, vmaddr)
            vm_end = max(vm_end, vmaddr + vmsize)
            sect_off = off + 72
            for _ in range(nsects):
                sect = struct.unpack_from("<16s16sQQIIIIIII", cmds, sect_off)
                offset = sect[4]
                size = sect[3]
                file_end = max(file_end, offset + size)
                sect_off += 80
        elif cmd == LC_SYMTAB:
            symoff, nsyms, stroff, strsize = struct.unpack_from("<IIII", cmds, off + 8)
            file_end = max(file_end, symoff + strsize)
        elif cmd == LC_DYSYMTAB:
            fields = struct.unpack_from("<IIIIIIIIIIIIIIIIII", cmds, off + 8)
            for val, size in [
                (fields[6], fields[7] * 0x10),
                (fields[8], fields[9] * 0x38),
                (fields[10], fields[11] * 4),
                (fields[12], fields[13] * 4),
                (fields[14], fields[15] * 8),
                (fields[16], fields[17] * 8),
            ]:
                if val:
                    file_end = max(file_end, val + size)
        elif cmd in LINKEDIT_DATA_CMDS:
            dataoff, datasize = struct.unpack_from("<II", cmds, off + 8)
            file_end = max(file_end, dataoff + datasize)

    if file_base is None:
        file_base = 0
    return file_base, file_end, vm_base or 0, vm_end, segment_names


def _load_world_id(repo_root: Path) -> Optional[str]:
    baseline = repo_root / "book" / "world" / "sonoma-14.4.1-23E224-arm64" / "world-baseline.json"
    if not baseline.exists():
        return None
    try:
        data = json.loads(baseline.read_text())
    except Exception:
        return None
    return data.get("world_id")


def _decode_kernel_cache_ptr(raw: int) -> Dict[str, int | bool]:
    target = raw & 0x3FFFFFFF
    cache_level = (raw >> 30) & 0x3
    next_delta = (raw >> 32) & 0xFFF
    is_auth = (raw >> 63) & 0x1
    return {
        "target": target,
        "cache_level": cache_level,
        "next_delta": next_delta,
        "is_auth": bool(is_auth),
    }


def _iter_fixups(
    kc_path: Path,
    segments: List[Segment],
    fixups_data: bytes,
    entries_by_range: List[Tuple[int, int, str]],
    base_pointers: Dict[int, int | None],
    out_path: Path,
) -> Dict[str, int | Dict[str, int] | Dict[str, Dict[str, int]]]:
    fixups_version, starts_offset, imports_offset, symbols_offset, imports_count, imports_format, symbols_format = struct.unpack_from(
        "<IIIIIII", fixups_data, 0
    )
    seg_count = struct.unpack_from("<I", fixups_data, starts_offset)[0]
    seg_info_offsets = [
        struct.unpack_from("<I", fixups_data, starts_offset + 4 + i * 4)[0] for i in range(seg_count)
    ]

    pointer_counts: Dict[str, int] = {}
    per_segment_counts: Dict[str, int] = {}
    total = 0
    page_coverage: Dict[str, Dict[str, int]] = {}
    max_chain_len = 0

    def find_entry(vmaddr: int) -> Optional[str]:
        if not entries_by_range:
            return None
        # entries_by_range sorted by start
        lo = 0
        hi = len(entries_by_range) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            start, end, entry_id = entries_by_range[mid]
            if vmaddr < start:
                hi = mid - 1
            elif vmaddr >= end:
                lo = mid + 1
            else:
                return entry_id
        return None

    with kc_path.open("rb") as f, out_path.open("w") as out:
        for seg_index, info_off in enumerate(seg_info_offsets):
            if info_off == 0:
                continue
            seg_off = starts_offset + info_off
            size, page_size, pointer_format = struct.unpack_from("<IHH", fixups_data, seg_off)
            segment_offset = struct.unpack_from("<Q", fixups_data, seg_off + 8)[0]
            max_valid_pointer = struct.unpack_from("<I", fixups_data, seg_off + 16)[0]
            page_count = struct.unpack_from("<H", fixups_data, seg_off + 20)[0]
            page_starts_off = seg_off + 22
            page_starts = [
                struct.unpack_from("<H", fixups_data, page_starts_off + i * 2)[0] for i in range(page_count)
            ]

            if seg_index >= len(segments):
                seg_name = f"segment_{seg_index}"
                seg_vmaddr = 0
            else:
                seg_name = segments[seg_index].name
                seg_vmaddr = segments[seg_index].vmaddr

            fmt_key = f"{pointer_format}"
            pointer_counts[fmt_key] = pointer_counts.get(fmt_key, 0)
            per_segment_counts[seg_name] = per_segment_counts.get(seg_name, 0)
            page_coverage[seg_name] = page_coverage.get(
                seg_name,
                {
                    "page_size": page_size,
                    "page_count": page_count,
                    "pages_with_fixups": 0,
                    "fixups": 0,
                },
            )

            for page_index, page_start in enumerate(page_starts):
                if page_start == 0xFFFF:
                    continue
                page_coverage[seg_name]["pages_with_fixups"] += 1
                chain_fileoff = segment_offset + page_index * page_size + page_start
                chain_vmaddr = seg_vmaddr + page_index * page_size + page_start
                chain_steps = 0
                while True:
                    f.seek(chain_fileoff)
                    raw_bytes = f.read(8)
                    if len(raw_bytes) != 8:
                        break
                    raw = struct.unpack_from("<Q", raw_bytes, 0)[0]
                    decoded: Dict[str, int | bool] = {}
                    if pointer_format == 8:
                        decoded = _decode_kernel_cache_ptr(raw)
                        next_delta = int(decoded["next_delta"])
                        next_off = next_delta * 4
                    else:
                        next_delta = 0
                        next_off = 0

                    resolved_guess = None
                    resolved_unsigned = None
                    base_ptr = None
                    if pointer_format == 8:
                        target = int(decoded["target"])
                        cache_level = int(decoded["cache_level"])
                        base_ptr = base_pointers.get(cache_level)
                        if base_ptr is not None:
                            resolved_unsigned = base_ptr + target
                            resolved_guess = resolved_unsigned

                    record = {
                        "segment_index": seg_index,
                        "segment_name": seg_name,
                        "pointer_format": pointer_format,
                        "page_index": page_index,
                        "page_start": page_start,
                        "fileoff": chain_fileoff,
                        "vmaddr": chain_vmaddr,
                        "raw": raw,
                        "decoded": decoded,
                        "next_offset": next_off,
                        "resolved_guess": resolved_guess,
                        "resolved_unsigned": resolved_unsigned,
                        "resolved_base": base_ptr,
                        "owner_entry": find_entry(chain_vmaddr),
                    }
                    out.write(json.dumps(record) + "\n")
                    total += 1
                    pointer_counts[fmt_key] = pointer_counts.get(fmt_key, 0) + 1
                    per_segment_counts[seg_name] = per_segment_counts.get(seg_name, 0) + 1
                    page_coverage[seg_name]["fixups"] += 1

                    chain_steps += 1
                    if chain_steps > max_chain_len:
                        max_chain_len = chain_steps
                    if next_off == 0 or chain_steps > 10000:
                        break
                    chain_fileoff += next_off
                    chain_vmaddr += next_off

    return {
        "total_fixups": total,
        "pointer_format_counts": pointer_counts,
        "segment_counts": per_segment_counts,
        "page_coverage": page_coverage,
        "max_chain_len": max_chain_len,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build KC fileset + chained-fixups truth layer.")
    parser.add_argument("--build-id", default="14.4.1-23E224", help="Sandbox-private build ID.")
    parser.add_argument("--out-dir", default="book/experiments/mac-policy-registration/out", help="Output dir.")
    args = parser.parse_args()

    repo_root = path_utils.find_repo_root()
    kc_path = path_utils.ensure_absolute(
        repo_root / f"dumps/Sandbox-private/{args.build_id}/kernel/BootKernelCollection.kc"
    )
    out_dir = path_utils.ensure_absolute(args.out_dir, repo_root)
    out_dir.mkdir(parents=True, exist_ok=True)

    world_id = _load_world_id(repo_root)

    header, cmds = _load_cmd_bytes(kc_path, 0)
    segments = _parse_segments(cmds, header.ncmds)
    fileset_entries = _parse_fileset_entries(cmds, header.ncmds)
    fileset_entries_sorted = sorted(fileset_entries, key=lambda e: int(e["fileoff"]))

    entries_out: List[Dict[str, object]] = []
    for entry in fileset_entries_sorted:
        entry_off = int(entry["fileoff"])
        entry_header, entry_cmds = _load_cmd_bytes(kc_path, entry_off)
        file_base, file_end, vm_base, vm_end, seg_names = _compute_entry_bounds(entry_cmds, entry_header.ncmds)
        entries_out.append(
            {
                "entry_id": entry["entry_id"],
                "fileoff": entry_off,
                "vmaddr": int(entry["vmaddr"]),
                "segment_count": len(seg_names),
                "segment_names": seg_names,
                "file_span": {"start": file_base, "end": file_end, "size": file_end - file_base},
                "vmaddr_span": {"start": vm_base, "end": vm_end, "size": vm_end - vm_base},
            }
        )

    entries_by_range = sorted(
        [(e["vmaddr_span"]["start"], e["vmaddr_span"]["end"], e["entry_id"]) for e in entries_out],
        key=lambda x: x[0],
    )

    fileset_index = {
        "meta": {
            "world_id": world_id,
            "build_id": args.build_id,
            "kc_path": path_utils.to_repo_relative(kc_path, repo_root),
            "filetype": header.filetype,
            "filetype_name": "MH_FILESET" if header.filetype == MH_FILESET else "unknown",
            "ncmds": header.ncmds,
            "sizeofcmds": header.sizeofcmds,
            "segment_count": len(segments),
            "fileset_entry_count": len(entries_out),
        },
        "segments": [
            {
                "name": seg.name,
                "vmaddr": seg.vmaddr,
                "vmsize": seg.vmsize,
                "fileoff": seg.fileoff,
                "filesize": seg.filesize,
            }
            for seg in segments
        ],
        "entries": entries_out,
    }

    fileset_index_path = out_dir / "kc_fileset_index.json"
    fileset_index_path.write_text(json.dumps(fileset_index, indent=2, sort_keys=True))

    # Fixups
    fixups = None
    for cmd, cmdsize, off in _iter_load_commands(cmds, header.ncmds):
        if cmd == LC_DYLD_CHAINED_FIXUPS:
            dataoff, datasize = struct.unpack_from("<II", cmds, off + 8)
            fixups = (dataoff, datasize)
            break
    if not fixups:
        print("No LC_DYLD_CHAINED_FIXUPS found")
        return 1

    with kc_path.open("rb") as f:
        f.seek(fixups[0])
        fixups_data = f.read(fixups[1])

    base_pointers: Dict[int, int | None] = {0: None, 1: None, 2: None, 3: None}
    if segments:
        min_vmaddr = min(seg.vmaddr for seg in segments)
        base_pointers[0] = min_vmaddr & ~0x3FFF

    fixups_out_path = out_dir / "kc_fixups.jsonl"
    fixups_summary = _iter_fixups(
        kc_path=kc_path,
        segments=segments,
        fixups_data=fixups_data,
        entries_by_range=entries_by_range,
        base_pointers=base_pointers,
        out_path=fixups_out_path,
    )

    fixups_version, starts_offset, imports_offset, symbols_offset, imports_count, imports_format, symbols_format = struct.unpack_from(
        "<IIIIIII", fixups_data, 0
    )
    fixups_summary_out = {
        "meta": {
            "world_id": world_id,
            "build_id": args.build_id,
            "kc_path": path_utils.to_repo_relative(kc_path, repo_root),
            "fixups_dataoff": fixups[0],
            "fixups_datasize": fixups[1],
            "fixups_version": fixups_version,
            "starts_offset": starts_offset,
            "imports_offset": imports_offset,
            "symbols_offset": symbols_offset,
            "imports_count": imports_count,
            "imports_format": imports_format,
            "symbols_format": symbols_format,
            "fixups_jsonl": path_utils.to_repo_relative(fixups_out_path, repo_root),
            "base_pointers": base_pointers,
            "decode_assumptions": {
                "pointer_format_8": {
                    "target_bits": 30,
                    "cache_level_bits": [30, 31],
                    "next_bits": [32, 43],
                    "next_scale": 4,
                    "resolved_guess": "base_pointers[cache_level] + target (when base_pointers is known)",
                    "status": "under_exploration",
                }
            },
        },
        "fixup_counts": fixups_summary,
    }

    fixups_summary_path = out_dir / "kc_fixups_summary.json"
    fixups_summary_path.write_text(json.dumps(fixups_summary_out, indent=2, sort_keys=True))

    print("Wrote", path_utils.to_repo_relative(fileset_index_path, repo_root))
    print("Wrote", path_utils.to_repo_relative(fixups_summary_path, repo_root))
    print("Wrote", path_utils.to_repo_relative(fixups_out_path, repo_root))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
