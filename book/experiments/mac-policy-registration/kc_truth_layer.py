#!/usr/bin/env python3
"""
Build a KC "truth layer" by enumerating fileset entries and decoding chained fixups.

Outputs (default under book/experiments/mac-policy-registration/out):
- kc_fileset_index.json (fileset entries + segment interval map)
- kc_fixups_summary.json
- kc_fixups.jsonl (compact by default; use --fixups-mode lite/full for larger records)

Notes:
- Fixup decoding for pointer_format=8 follows the XNU field layout and chain
  stepping (next*4). Any base-pointer inference beyond cache level 0 remains
  under exploration until validated against additional witnesses.
- Address mapping is done in KC on-disk vmaddr space (pre-adjust / slide=0).
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
DYLD_CHAINED_PTR_START_NONE = 0xFFFF
DYLD_CHAINED_PTR_START_MULTI = 0x8000


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


def _compute_entry_bounds(cmds: bytes, ncmds: int) -> Tuple[int, int, int, int, List[str], List[Dict[str, object]]]:
    """Return (file_base, file_end, vm_base, vm_end, segment_names, segment_details)."""
    file_base: Optional[int] = None
    file_end = 0
    vm_base: Optional[int] = None
    vm_end = 0
    segment_names: List[str] = []
    segment_details: List[Dict[str, object]] = []

    for cmd, cmdsize, off in _iter_load_commands(cmds, ncmds):
        if cmd == LC_SEGMENT_64:
            segname, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags = struct.unpack_from(
                "<16sQQQQIIII", cmds, off + 8
            )
            segname = segname.split(b"\x00", 1)[0].decode("ascii", errors="ignore")
            segment_names.append(segname)
            segment_details.append(
                {
                    "name": segname,
                    "vmaddr": int(vmaddr),
                    "vmsize": int(vmsize),
                    "vmaddr_end": int(vmaddr + vmsize),
                    "fileoff": int(fileoff),
                    "filesize": int(filesize),
                    "is_exec_heuristic": segname in ("__TEXT", "__TEXT_EXEC"),
                }
            )
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
    return file_base, file_end, vm_base or 0, vm_end, segment_names, segment_details


def _load_world_id(repo_root: Path) -> Optional[str]:
    baseline = repo_root / "book" / "world" / "sonoma-14.4.1-23E224-arm64" / "world.json"
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
    diversity = (raw >> 32) & 0xFFFF
    addr_div = (raw >> 48) & 0x1
    key = (raw >> 49) & 0x3
    next_delta = (raw >> 51) & 0xFFF
    is_auth = (raw >> 63) & 0x1
    return {
        "target": target,
        "cache_level": cache_level,
        "diversity": diversity,
        "addr_div": addr_div,
        "key": key,
        "next_delta": next_delta,
        "is_auth": bool(is_auth),
    }


def _build_segment_intervals(
    entries: List[Dict[str, object]],
    overlap_limit: int = 20,
    include_linkedit: bool = False,
) -> Tuple[List[Dict[str, object]], List[Dict[str, object]], int, Dict[str, int]]:
    intervals: List[Dict[str, object]] = []
    skipped_counts: Dict[str, int] = {}
    for entry in entries:
        entry_id = entry.get("entry_id")
        for seg in entry.get("segment_details") or []:
            seg_name = seg.get("name")
            if not include_linkedit and seg_name == "__LINKEDIT":
                skipped_counts[seg_name] = skipped_counts.get(seg_name, 0) + 1
                continue
            start = seg.get("vmaddr")
            end = seg.get("vmaddr_end")
            if start is None or end is None or end <= start:
                continue
            intervals.append(
                {
                    "start": int(start),
                    "end": int(end),
                    "entry_id": entry_id,
                    "segment_name": seg_name,
                    "is_exec": bool(seg.get("is_exec_heuristic")),
                }
            )
    intervals.sort(key=lambda item: item["start"])
    overlaps: List[Dict[str, object]] = []
    overlap_total = 0
    for idx in range(1, len(intervals)):
        prev = intervals[idx - 1]
        cur = intervals[idx]
        if cur["start"] < prev["end"]:
            overlap_total += 1
            if len(overlaps) < overlap_limit:
                overlaps.append(
                    {
                        "prev": prev,
                        "cur": cur,
                    }
                )
            else:
                continue
    return intervals, overlaps, overlap_total, skipped_counts


def _find_interval(intervals: List[Dict[str, object]], vmaddr: int) -> Tuple[Optional[Dict[str, object]], int]:
    if not intervals:
        return None, 0
    lo = 0
    hi = len(intervals) - 1
    match_idx = None
    while lo <= hi:
        mid = (lo + hi) // 2
        start = intervals[mid]["start"]
        end = intervals[mid]["end"]
        if vmaddr < start:
            hi = mid - 1
        elif vmaddr >= end:
            lo = mid + 1
        else:
            match_idx = mid
            break
    if match_idx is None:
        return None, 0
    matches = [intervals[match_idx]]
    idx = match_idx - 1
    while idx >= 0 and intervals[idx]["end"] > vmaddr:
        if intervals[idx]["start"] <= vmaddr < intervals[idx]["end"]:
            matches.append(intervals[idx])
        idx -= 1
    idx = match_idx + 1
    while idx < len(intervals) and intervals[idx]["start"] <= vmaddr:
        if intervals[idx]["start"] <= vmaddr < intervals[idx]["end"]:
            matches.append(intervals[idx])
        idx += 1
    matches = sorted(matches, key=lambda item: item["end"] - item["start"])
    return matches[0], len(matches)


def _collect_fixups(
    kc_path: Path,
    segments: List[Segment],
    fixups_data: bytes,
) -> Tuple[List[Dict[str, object]], Dict[str, object]]:
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
    cache_level_counts: Dict[str, int] = {}
    page_start_mode_counts = {"single": 0, "multi": 0}
    multi_start_pages: List[Dict[str, int]] = []
    fixups: List[Dict[str, object]] = []

    def _read_u16(offset: int) -> Optional[int]:
        if offset < 0 or offset + 2 > len(fixups_data):
            return None
        return struct.unpack_from("<H", fixups_data, offset)[0]

    with kc_path.open("rb") as f:
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
                if page_start == DYLD_CHAINED_PTR_START_NONE:
                    continue
                chain_offsets: List[int] = []
                if page_start & DYLD_CHAINED_PTR_START_MULTI:
                    page_start_mode_counts["multi"] += 1
                    if len(multi_start_pages) < 20:
                        multi_start_pages.append(
                            {
                                "segment_index": seg_index,
                                "page_index": page_index,
                                "page_start": page_start,
                            }
                        )
                    continue
                else:
                    page_start_mode_counts["single"] += 1
                    chain_offsets.append(page_start)
                if not chain_offsets:
                    continue
                page_coverage[seg_name]["pages_with_fixups"] += 1
                for chain_start in chain_offsets:
                    chain_fileoff = segment_offset + page_index * page_size + chain_start
                    chain_vmaddr = seg_vmaddr + page_index * page_size + chain_start
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
                            cache_level_counts[str(decoded["cache_level"])] = cache_level_counts.get(
                                str(decoded["cache_level"]), 0
                            ) + 1
                        else:
                            next_delta = 0
                            next_off = 0

                        record = {
                            "segment_index": seg_index,
                            "segment_name": seg_name,
                            "pointer_format": pointer_format,
                            "page_index": page_index,
                            "page_start": page_start,
                            "page_chain_start": chain_start,
                            "fileoff": chain_fileoff,
                            "vmaddr": chain_vmaddr,
                            "raw": raw,
                            "decoded": decoded,
                            "next_offset": next_off,
                        }
                        fixups.append(record)
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
        "fixups": fixups,
        "total_fixups": total,
        "pointer_format_counts": pointer_counts,
        "segment_counts": per_segment_counts,
        "page_coverage": page_coverage,
        "max_chain_len": max_chain_len,
        "cache_level_counts": cache_level_counts,
        "page_start_mode_counts": page_start_mode_counts,
        "multi_start_pages": multi_start_pages,
    }


def _coverage_for_base(
    fixups: List[Dict[str, object]],
    segment_intervals: List[Dict[str, object]],
    base_ptr: Optional[int],
    cache_level: int,
) -> Tuple[int, int]:
    if base_ptr is None:
        return 0, 0
    hits = 0
    total = 0
    for rec in fixups:
        if rec.get("pointer_format") != 8:
            continue
        decoded = rec.get("decoded") or {}
        lvl = decoded.get("cache_level")
        target = decoded.get("target")
        if lvl is None or target is None:
            continue
        if int(lvl) != cache_level:
            continue
        total += 1
        resolved = base_ptr + int(target)
        if _find_interval(segment_intervals, resolved)[0] is not None:
            hits += 1
    return hits, total


def _infer_base_pointers(
    fixups: List[Dict[str, object]],
    segment_intervals: List[Dict[str, object]],
    base_pointers: Dict[int, int | None],
    threshold: float = 0.95,
) -> Tuple[Dict[int, int | None], Dict[str, object]]:
    inferred = dict(base_pointers)
    base0 = inferred.get(0)
    levels = sorted(inferred.keys())
    inference = {"threshold": threshold, "base0": base0, "coverage_metric": "resolved_in_entry/total", "levels": {}}
    for level in levels:
        hits, total = _coverage_for_base(fixups, segment_intervals, base0, level)
        coverage = (float(hits) / float(total)) if total else 0.0
        entry = {
            "coverage_hits": hits,
            "coverage_total": total,
            "coverage": coverage,
            "base_candidate": base0,
            "chosen_base": inferred.get(level),
            "status": "seed" if level == 0 else "unresolved",
        }
        if level != 0 and total and coverage >= threshold:
            inferred[level] = base0
            entry["chosen_base"] = base0
            entry["status"] = "inferred_base0"
        inference["levels"][str(level)] = entry
    return inferred, inference


def _write_fixups(
    fixups: List[Dict[str, object]],
    segment_intervals: List[Dict[str, object]],
    entries_by_id: Dict[str, Dict[str, object]],
    base_pointers: Dict[int, int | None],
    out_path: Path,
    mode: str = "full",
) -> Dict[str, object]:
    resolved_counts = {
        "resolved_in_entry": 0,
        "resolved_in_exec": 0,
        "resolved_outside": 0,
        "unresolved_unknown_base": 0,
        "resolved_ambiguous": 0,
    }
    resolved_counts_by_cache_level: Dict[str, Dict[str, int]] = {}

    def find_entry_segment(vmaddr: int) -> Tuple[Optional[str], Optional[str], Optional[bool], int]:
        match, count = _find_interval(segment_intervals, vmaddr)
        if not match:
            return None, None, None, 0
        return (
            match.get("entry_id"),
            match.get("segment_name"),
            bool(match.get("is_exec")) if match.get("is_exec") is not None else None,
            count,
        )

    def bump(level: Optional[int], key: str) -> None:
        if level is None:
            return
        bucket = resolved_counts_by_cache_level.setdefault(
            str(level),
            {
                "resolved_in_entry": 0,
                "resolved_in_exec": 0,
                "resolved_outside": 0,
                "unresolved_unknown_base": 0,
                "resolved_ambiguous": 0,
            },
        )
        bucket[key] = bucket.get(key, 0) + 1

    with out_path.open("w") as out:
        for rec in fixups:
            decoded = rec.get("decoded") or {}
            pointer_format = rec.get("pointer_format")
            resolved_guess = None
            resolved_unsigned = None
            base_ptr = None
            cache_level = None
            if pointer_format == 8:
                cache_level = decoded.get("cache_level")
                target = decoded.get("target")
                if cache_level is not None:
                    base_ptr = base_pointers.get(int(cache_level))
                if base_ptr is not None and target is not None:
                    resolved_unsigned = base_ptr + int(target)
                    resolved_guess = resolved_unsigned
                else:
                    resolved_counts["unresolved_unknown_base"] += 1
                    bump(int(cache_level) if cache_level is not None else None, "unresolved_unknown_base")

            owner_match, owner_count = _find_interval(segment_intervals, int(rec["vmaddr"]))
            owner_entry = owner_match.get("entry_id") if owner_match else None
            if mode == "compact":
                record = {
                    "v": rec["vmaddr"],
                    "r": resolved_unsigned,
                }
            elif mode == "lite":
                decoded_lite = {}
                if pointer_format == 8:
                    decoded_lite = {
                        "target": decoded.get("target"),
                        "cache_level": decoded.get("cache_level"),
                        "is_auth": decoded.get("is_auth"),
                    }
                record = {
                    "vmaddr": rec["vmaddr"],
                    "pointer_format": pointer_format,
                    "decoded": decoded_lite,
                    "resolved_guess": resolved_guess,
                    "resolved_unsigned": resolved_unsigned,
                }
            else:
                record = dict(rec)
                record.update(
                    {
                        "resolved_guess": resolved_guess,
                        "resolved_unsigned": resolved_unsigned,
                        "resolved_base": base_ptr,
                        "owner_entry": owner_entry,
                        "owner_segment": owner_match.get("segment_name") if owner_match else None,
                        "owner_ambiguous": owner_count if owner_count > 1 else 0,
                    }
                )
            out.write(json.dumps(record) + "\n")

            if resolved_unsigned is None:
                continue
            entry_id, segment_name, is_exec, amb_count = find_entry_segment(resolved_unsigned)
            if amb_count > 1:
                resolved_counts["resolved_ambiguous"] += 1
                bump(int(cache_level) if cache_level is not None else None, "resolved_ambiguous")
            if entry_id:
                resolved_counts["resolved_in_entry"] += 1
                bump(int(cache_level) if cache_level is not None else None, "resolved_in_entry")
                if is_exec:
                    resolved_counts["resolved_in_exec"] += 1
                    bump(int(cache_level) if cache_level is not None else None, "resolved_in_exec")
            else:
                resolved_counts["resolved_outside"] += 1
                bump(int(cache_level) if cache_level is not None else None, "resolved_outside")

    return {
        "resolved_counts": resolved_counts,
        "resolved_counts_by_cache_level": resolved_counts_by_cache_level,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build KC fileset + chained-fixups truth layer.")
    parser.add_argument("--build-id", default="14.4.1-23E224", help="Sandbox-private build ID.")
    parser.add_argument("--out-dir", default="book/experiments/mac-policy-registration/out", help="Output dir.")
    parser.add_argument(
        "--fixups-mode",
        choices=("compact", "lite", "full"),
        default="compact",
        help="Write compact, lite, or full per-fixup records (default: compact).",
    )
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
        file_base, file_end, vm_base, vm_end, seg_names, seg_details = _compute_entry_bounds(
            entry_cmds, entry_header.ncmds
        )
        entries_out.append(
            {
                "entry_id": entry["entry_id"],
                "fileoff": entry_off,
                "vmaddr": int(entry["vmaddr"]),
                "segment_count": len(seg_names),
                "segment_names": seg_names,
                "segment_details": seg_details,
                "file_span": {"start": file_base, "end": file_end, "size": file_end - file_base},
                "vmaddr_span": {"start": vm_base, "end": vm_end, "size": vm_end - vm_base},
            }
        )

    segment_intervals, interval_overlaps, interval_overlap_total, interval_skipped = _build_segment_intervals(
        entries_out,
        include_linkedit=False,
    )
    entries_by_id = {e["entry_id"]: e for e in entries_out}

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
            "vmaddr_space": "kc_vmaddr_pre_adjust",
            "vmaddr_space_note": "Static on-disk vmaddr values (slide=0) used for all address mapping.",
            "segment_interval_count": len(segment_intervals),
            "segment_interval_overlap_count": len(interval_overlaps),
            "segment_interval_overlap_total": interval_overlap_total,
            "segment_interval_excluded_segments": interval_skipped,
            "segment_interval_policy": "exclude __LINKEDIT (shared range across entries)",
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
        "segment_intervals": segment_intervals,
        "segment_interval_overlaps": interval_overlaps,
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

    collected = _collect_fixups(
        kc_path=kc_path,
        segments=segments,
        fixups_data=fixups_data,
    )
    fixups = collected.pop("fixups")

    cache_level_counts = collected.get("cache_level_counts", {}) or {}
    cache_total = sum(int(val) for val in cache_level_counts.values()) if cache_level_counts else 0
    cache_zero = int(cache_level_counts.get("0") or 0)
    cache_nonzero = cache_total - cache_zero
    cache_nonzero_fraction = (float(cache_nonzero) / cache_total) if cache_total else 0.0
    cache_nonzero_dominates = cache_total > 0 and cache_nonzero > cache_zero
    if cache_nonzero_dominates:
        base_inference = {
            "status": "skipped_sanity_gate",
            "cache_level_counts": cache_level_counts,
            "cache_nonzero_fraction": cache_nonzero_fraction,
            "note": "Non-zero cache_level dominates; skipping inference pending fixups decode validation.",
        }
        for level in (1, 2, 3):
            base_pointers[level] = None
    else:
        base_pointers, base_inference = _infer_base_pointers(
            fixups,
            segment_intervals,
            base_pointers,
            threshold=0.95,
        )

    fixups_out_path = out_dir / "kc_fixups.jsonl"
    resolved_summary = _write_fixups(
        fixups=fixups,
        segment_intervals=segment_intervals,
        entries_by_id=entries_by_id,
        base_pointers=base_pointers,
        out_path=fixups_out_path,
        mode=args.fixups_mode,
    )
    fixups_summary = dict(collected)
    fixups_summary.update(resolved_summary)

    fixups_version, starts_offset, imports_offset, symbols_offset, imports_count, imports_format, symbols_format = struct.unpack_from(
        "<IIIIIII", fixups_data, 0
    )
    resolved_counts = resolved_summary.get("resolved_counts") or {}
    total_fixups = int(fixups_summary.get("total_fixups") or 0)
    sanity = {
        "pointer_format_counts": fixups_summary.get("pointer_format_counts") or {},
        "cache_level_counts": cache_level_counts,
        "cache_nonzero_fraction": cache_nonzero_fraction,
        "cache_nonzero_dominates": cache_nonzero_dominates,
        "page_start_mode_counts": fixups_summary.get("page_start_mode_counts") or {},
        "multi_start_pages_count": len(fixups_summary.get("multi_start_pages") or []),
        "resolved_counts": resolved_counts,
    }
    if total_fixups:
        sanity["resolved_in_entry_fraction"] = float(resolved_counts.get("resolved_in_entry") or 0) / total_fixups
        sanity["resolved_in_exec_fraction"] = float(resolved_counts.get("resolved_in_exec") or 0) / total_fixups
        sanity["resolved_outside_fraction"] = float(resolved_counts.get("resolved_outside") or 0) / total_fixups
        sanity["unresolved_unknown_base_fraction"] = (
            float(resolved_counts.get("unresolved_unknown_base") or 0) / total_fixups
        )
        sanity["resolved_ambiguous_fraction"] = float(resolved_counts.get("resolved_ambiguous") or 0) / total_fixups
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
            "fixups_jsonl_mode": args.fixups_mode,
            "base_pointers": base_pointers,
            "base_pointer_inference": base_inference,
            "vmaddr_space": "kc_vmaddr_pre_adjust",
            "vmaddr_space_note": "All fixup vmaddr values are reported in KC on-disk address space (slide=0).",
            "segment_interval_policy": "exclude __LINKEDIT (shared range across entries)",
            "decode_assumptions": {
                "pointer_format_8": {
                    "target_bits": 30,
                    "cache_level_bits": [30, 31],
                    "diversity_bits": [32, 47],
                    "addr_div_bit": 48,
                    "key_bits": [49, 50],
                    "next_bits": [51, 62],
                    "next_scale": 4,
                    "resolved_guess": "base_pointers[cache_level] + target (when base_pointers is known)",
                    "status": "partial",
                }
            },
            "page_start_modes": {
                "single": "page_start is direct chain offset",
                "multi": "page_start flagged as DYLD_CHAINED_PTR_START_MULTI (unexpected for BootKC)",
                "status": "partial",
            },
        },
        "fixup_counts": fixups_summary,
        "sanity": sanity,
    }

    fixups_summary_path = out_dir / "kc_fixups_summary.json"
    fixups_summary_path.write_text(json.dumps(fixups_summary_out, indent=2, sort_keys=True))

    print("Wrote", path_utils.to_repo_relative(fileset_index_path, repo_root))
    print("Wrote", path_utils.to_repo_relative(fixups_summary_path, repo_root))
    print("Wrote", path_utils.to_repo_relative(fixups_out_path, repo_root))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
