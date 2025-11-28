#!/usr/bin/env python3
"""
Harvest the Filter Vocabulary from the extracted libsandbox.dylib.

Approach:
- Use `nm` to locate `_filter_info` (array of filter descriptors).
- Map vmaddrs to file offsets via `otool -l` segment data.
- Treat each 0x20-byte entry as a descriptor; the first pointer is the filter
  name (pointer-auth masked). Skip zero/empty entries and stop at the first
  all-zero record.
- Resolve names from `__TEXT.__cstring` using the shared-cache base.

Outputs:
- book/experiments/vocab-from-cache/out/filter_names.json
"""

from __future__ import annotations

import json
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List


LIB_PATH = Path("book/experiments/vocab-from-cache/extracted/usr/lib/libsandbox.1.dylib")
OUT_PATH = Path("book/experiments/vocab-from-cache/out/filter_names.json")
ENTRY_SIZE = 0x20  # bytes per filter_info entry


@dataclass
class Segment:
    name: str
    vmaddr: int
    vmsize: int
    fileoff: int
    filesize: int


def parse_segments(path: Path) -> List[Segment]:
    out = subprocess.check_output(["otool", "-l", str(path)], text=True)
    segs: List[Segment] = []
    current: Dict[str, str] = {}
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("cmd LC_SEGMENT_64"):
            current = {}
        elif line.startswith("segname"):
            current["name"] = line.split()[1]
        elif line.startswith("vmaddr"):
            current["vmaddr"] = line.split()[1]
        elif line.startswith("vmsize"):
            current["vmsize"] = line.split()[1]
        elif line.startswith("fileoff"):
            current["fileoff"] = line.split()[1]
        elif line.startswith("filesize"):
            current["filesize"] = line.split()[1]
        elif line.startswith("flags") and current:
            required = {"name", "vmaddr", "vmsize", "fileoff", "filesize"}
            if required.issubset(current):
                segs.append(
                    Segment(
                        name=current["name"],
                        vmaddr=int(current["vmaddr"], 16),
                        vmsize=int(current["vmsize"], 16),
                        fileoff=int(current["fileoff"]),
                        filesize=int(current["filesize"]),
                    )
                )
            current = {}
    return segs


def vm_to_file(vm: int, segments: List[Segment]) -> int:
    for seg in segments:
        if seg.vmaddr <= vm < seg.vmaddr + seg.vmsize:
            return seg.fileoff + (vm - seg.vmaddr)
    raise ValueError(f"vmaddr {hex(vm)} not mapped to any segment")


def symbol_vmaddr(path: Path, symbol: str) -> int:
    out = subprocess.check_output(["nm", "-nm", str(path)], text=True)
    for line in out.splitlines():
        if symbol in line.split()[-1]:
            return int(line.split()[0], 16)
    raise ValueError(f"symbol {symbol} not found in {path}")


def harvest_filter_names(path: Path) -> Dict[str, object]:
    data = path.read_bytes()
    segments = parse_segments(path)
    text_seg = next(s for s in segments if s.name == "__TEXT")
    shared_cache_base = text_seg.vmaddr & 0xFFFFFFFFF0000000

    filter_info_vm = symbol_vmaddr(path, "_filter_info")
    filter_info_off = vm_to_file(filter_info_vm, segments)

    names: List[str] = []
    seen_nonzero = False
    for idx in range(0, 256):  # generous upper bound
        off = filter_info_off + idx * ENTRY_SIZE
        chunk = data[off : off + ENTRY_SIZE]
        if len(chunk) < ENTRY_SIZE:
            break
        if all(b == 0 for b in chunk):
            if seen_nonzero:
                break
            else:
                continue
        seen_nonzero = True
        name_ptr = struct.unpack_from("<Q", chunk)[0] & 0xFFFFFFFFFFFF
        if name_ptr == 0:
            continue
        vmaddr = name_ptr + shared_cache_base
        name_off = vm_to_file(vmaddr, segments)
        end = data.find(b"\x00", name_off)
        names.append(data[name_off:end].decode("ascii", errors="ignore"))

    return {
        "source": str(path),
        "count": len(names),
        "names": names,
        "filter_info_vm": hex(filter_info_vm),
        "filter_info_off": filter_info_off,
        "text_vmaddr": hex(text_seg.vmaddr),
        "shared_cache_base": hex(shared_cache_base),
    }


def main() -> None:
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    vocab = harvest_filter_names(LIB_PATH)
    OUT_PATH.write_text(json.dumps(vocab, indent=2))
    print(f"[+] wrote {OUT_PATH} ({vocab['count']} filters)")


if __name__ == "__main__":
    main()
