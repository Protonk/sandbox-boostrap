#!/usr/bin/env python3
"""
Generate canonical vocab mappings and raw name lists from the dyld-libs
libsandbox slice for the Sonoma baseline.

Outputs:
- book/evidence/graph/mappings/vocab/operation_names.json
- book/evidence/graph/mappings/vocab/filter_names.json
- book/evidence/graph/mappings/vocab/ops.json
- book/evidence/graph/mappings/vocab/filters.json
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from book.api import path_utils
from book.api import evidence_tiers
from book.api import world as world_mod
LIB_PATH = ROOT / "book/evidence/graph/mappings/dyld-libs/usr/lib/libsandbox.1.dylib"
OPS_PATH = ROOT / "book/evidence/graph/mappings/vocab/ops.json"
FILTERS_PATH = ROOT / "book/evidence/graph/mappings/vocab/filters.json"
OP_NAMES_PATH = ROOT / "book/evidence/graph/mappings/vocab/operation_names.json"
FILTER_NAMES_PATH = ROOT / "book/evidence/graph/mappings/vocab/filter_names.json"


@dataclass
class Segment:
    name: str
    vmaddr: int
    vmsize: int
    fileoff: int
    filesize: int


def load_world_id() -> str:
    world_doc, resolution = world_mod.load_world(repo_root=ROOT)
    return world_mod.require_world_id(world_doc, world_path=resolution.entry.world_path)


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
        parts = line.split()
        if parts and parts[-1] == symbol:
            return int(parts[0], 16)
    raise ValueError(f"symbol {symbol} not found in {path}")


def read_cstring(buf: bytes, offset: int) -> str:
    end = buf.find(b"\x00", offset)
    if end == -1:
        end = len(buf)
    return buf[offset:end].decode("ascii", errors="ignore")


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
        file_off = vm_to_file(vmaddr, segments)
        names.append(read_cstring(data, file_off))

    return {
        "names": names,
        "op_names_vm": hex(op_names_vm),
        "op_info_vm": hex(op_info_vm),
        "op_names_off": op_names_off,
        "op_info_off": op_info_off,
        "text_vmaddr": hex(text_seg.vmaddr),
        "shared_cache_base": hex(shared_cache_base),
    }


def harvest_filter_names(path: Path) -> Dict[str, object]:
    data = path.read_bytes()
    segments = parse_segments(path)
    text_seg = next(s for s in segments if s.name == "__TEXT")
    shared_cache_base = text_seg.vmaddr & 0xFFFFFFFFF0000000

    filter_info_vm = symbol_vmaddr(path, "_filter_info")
    filter_info_off = vm_to_file(filter_info_vm, segments)

    names: List[str] = []
    entry_size = 0x20
    seen_nonzero = False
    for idx in range(0, 256):
        off = filter_info_off + idx * entry_size
        chunk = data[off : off + entry_size]
        if len(chunk) < entry_size:
            break
        if all(b == 0 for b in chunk):
            if seen_nonzero:
                break
            continue
        seen_nonzero = True
        name_ptr = int.from_bytes(chunk[0:8], "little") & 0xFFFFFFFFFFFF
        if name_ptr == 0:
            continue
        vmaddr = name_ptr + shared_cache_base
        name_off = vm_to_file(vmaddr, segments)
        names.append(read_cstring(data, name_off))

    return {
        "names": names,
        "filter_info_vm": hex(filter_info_vm),
        "filter_info_off": filter_info_off,
        "text_vmaddr": hex(text_seg.vmaddr),
        "shared_cache_base": hex(shared_cache_base),
    }


def write_json(path: Path, payload: Dict[str, object]) -> None:
    path.write_text(json.dumps(payload, indent=2))


def main() -> int:
    if not LIB_PATH.exists():
        raise FileNotFoundError(f"missing libsandbox slice: {LIB_PATH}")
    world_id = load_world_id()
    source_rel = path_utils.to_repo_relative(LIB_PATH, ROOT)

    op_data = harvest_operation_names(LIB_PATH)
    filt_data = harvest_filter_names(LIB_PATH)
    op_names = op_data["names"]
    filter_names = filt_data["names"]
    ops_rel_path = path_utils.to_repo_relative(OPS_PATH, ROOT)
    filters_rel_path = path_utils.to_repo_relative(FILTERS_PATH, ROOT)

    op_names_doc: Dict[str, object] = {
        "source": source_rel,
        "count": len(op_names),
        "names": op_names,
        "op_names_vm": op_data["op_names_vm"],
        "op_info_vm": op_data["op_info_vm"],
        "op_names_off": op_data["op_names_off"],
        "op_info_off": op_data["op_info_off"],
        "text_vmaddr": op_data["text_vmaddr"],
        "shared_cache_base": op_data["shared_cache_base"],
    }
    filter_names_doc: Dict[str, object] = {
        "source": source_rel,
        "count": len(filter_names),
        "names": filter_names,
        "filter_info_vm": filt_data["filter_info_vm"],
        "filter_info_off": filt_data["filter_info_off"],
        "text_vmaddr": filt_data["text_vmaddr"],
        "shared_cache_base": filt_data["shared_cache_base"],
    }

    ops_doc = {
        "metadata": {
            "status": "ok",
            "tier": evidence_tiers.evidence_tier_for_artifact(path=ops_rel_path),
            "world_id": world_id,
        },
        "notes": f"Operation Vocabulary harvested from {source_rel} (_operation_names span).",
        "ops": [
            {"id": idx, "name": name, "source": source_rel} for idx, name in enumerate(op_names)
        ],
    }
    filters_doc = {
        "metadata": {
            "status": "ok",
            "tier": evidence_tiers.evidence_tier_for_artifact(path=filters_rel_path),
            "world_id": world_id,
        },
        "filters": [
            {"id": idx, "name": name, "source": source_rel} for idx, name in enumerate(filter_names)
        ],
    }

    write_json(OP_NAMES_PATH, op_names_doc)
    write_json(FILTER_NAMES_PATH, filter_names_doc)
    write_json(OPS_PATH, ops_doc)
    write_json(FILTERS_PATH, filters_doc)
    print(f"[+] wrote vocab mappings from {source_rel}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
