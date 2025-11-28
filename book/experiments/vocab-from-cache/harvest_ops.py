#!/usr/bin/env python3
"""
Harvest the Operation Vocabulary from the extracted libsandbox.dylib.

Steps:
- Locate `_operation_names` and `_operation_info` to recover the pointer array
  and count (the span between them, 8 bytes per entry).
- Decode each pointer (lower 48 bits plus shared-cache base) to a vmaddr.
- Convert vmaddrs into file offsets using segment metadata from `otool -l`.
- Read null-terminated strings from `__TEXT.__cstring` and emit the ordered list.

Outputs:
- book/experiments/vocab-from-cache/out/operation_names.json
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple


LIB_PATH = Path("book/experiments/vocab-from-cache/extracted/usr/lib/libsandbox.1.dylib")
OUT_PATH = Path("book/experiments/vocab-from-cache/out/operation_names.json")


@dataclass
class Segment:
    name: str
    vmaddr: int
    vmsize: int
    fileoff: int
    filesize: int


def parse_segments(path: Path) -> List[Segment]:
    """Parse `otool -l` output to recover segment vmaddr/fileoff mapping."""
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


def read_null_terminated(buf: bytes, offset: int) -> Tuple[str, int]:
    end = buf.find(b"\x00", offset)
    if end == -1:
        end = len(buf)
    return buf[offset:end].decode("ascii"), end + 1


def harvest_operation_names(path: Path) -> Dict[str, object]:
    data = path.read_bytes()
    segments = parse_segments(path)
    text_seg = next(s for s in segments if s.name == "__TEXT")
    shared_cache_base = text_seg.vmaddr & 0xFFFFFFFFF0000000

    op_names_vm = symbol_vmaddr(path, "_operation_names")
    op_info_vm = symbol_vmaddr(path, "_operation_info")
    op_names_off = vm_to_file(op_names_vm, segments)
    op_info_off = vm_to_file(op_info_vm, segments)

    count = (op_info_off - op_names_off) // 8
    names: List[str] = []
    for idx in range(count):
        ptr_bytes = data[op_names_off + idx * 8 : op_names_off + (idx + 1) * 8]
        ptr = int.from_bytes(ptr_bytes, "little")
        vmaddr = (ptr & 0xFFFFFFFFFFFF) + shared_cache_base
        file_off = vmaddr - text_seg.vmaddr
        name, _ = read_null_terminated(data, file_off)
        names.append(name)

    return {
        "source": str(path),
        "count": count,
        "names": names,
        "op_names_vm": hex(op_names_vm),
        "op_info_vm": hex(op_info_vm),
        "op_names_off": op_names_off,
        "op_info_off": op_info_off,
        "text_vmaddr": hex(text_seg.vmaddr),
        "shared_cache_base": hex(shared_cache_base),
    }


def main() -> None:
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    vocab = harvest_operation_names(LIB_PATH)
    OUT_PATH.write_text(json.dumps(vocab, indent=2))
    print(f"[+] wrote {OUT_PATH} ({vocab['count']} operations)")


if __name__ == "__main__":
    main()
