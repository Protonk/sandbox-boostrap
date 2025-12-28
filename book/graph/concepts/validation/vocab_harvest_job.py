"""
Harvest real Operation/Filter vocab from trimmed libsandbox dylib and verify
the canonical vocab mappings.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

from book.api.path_utils import find_repo_root, to_repo_relative

ROOT = find_repo_root(Path(__file__))
LIB_PATH = ROOT / "book/graph/mappings/dyld-libs/usr/lib/libsandbox.1.dylib"
OPS_MAP = ROOT / "book/graph/mappings/vocab/ops.json"
FILTERS_MAP = ROOT / "book/graph/mappings/vocab/filters.json"
META_PATH = ROOT / "book/graph/concepts/validation/out/metadata.json"
STATUS_PATH = ROOT / "book/graph/concepts/validation/out/vocab_status.json"

from book.graph.concepts.validation import registry
from book.graph.concepts.validation.registry import ValidationJob


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
        parts = line.split()
        if parts and parts[-1] == symbol:
            return int(parts[0], 16)
    raise ValueError(f"symbol {symbol} not found in {path}")


def read_cstring(buf: bytes, offset: int) -> str:
    end = buf.find(b"\x00", offset)
    if end == -1:
        end = len(buf)
    return buf[offset:end].decode("ascii", errors="ignore")


def harvest_operation_names(path: Path) -> List[str]:
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
    return names


def harvest_filter_names(path: Path) -> List[str]:
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
            else:
                continue
        seen_nonzero = True
        name_ptr = int.from_bytes(chunk[0:8], "little") & 0xFFFFFFFFFFFF
        if name_ptr == 0:
            continue
        vmaddr = name_ptr + shared_cache_base
        name_off = vm_to_file(vmaddr, segments)
        names.append(read_cstring(data, name_off))
    return names


def load_json(path: Path) -> Dict:
    return json.loads(path.read_text())


def ensure_mapping(names: List[str], mapping_path: Path, key: str) -> None:
    if not mapping_path.exists():
        raise FileNotFoundError(f"missing mapping file: {to_repo_relative(mapping_path, ROOT)}")
    mapping = load_json(mapping_path)
    status = (mapping.get("metadata") or {}).get("status") or mapping.get("status")
    if status != "ok":
        raise ValueError(f"{to_repo_relative(mapping_path, ROOT)} not ok: {status}")
    entries = mapping.get(key) or []
    if len(entries) != len(names):
        raise ValueError(f"{to_repo_relative(mapping_path, ROOT)} count mismatch: {len(entries)} vs extracted {len(names)}")
    entry_names = [e["name"] for e in entries]
    if entry_names != names:
        raise ValueError(f"{to_repo_relative(mapping_path, ROOT)} names diverge from extracted vocab")


def run_vocab_harvest_job():
    for required in [LIB_PATH, META_PATH, OPS_MAP, FILTERS_MAP]:
        if not required.exists():
            raise FileNotFoundError(f"missing required input: {to_repo_relative(required, ROOT)}")

    op_names = harvest_operation_names(LIB_PATH)
    filter_names = harvest_filter_names(LIB_PATH)
    ensure_mapping(op_names, OPS_MAP, "ops")
    ensure_mapping(filter_names, FILTERS_MAP, "filters")

    meta = load_json(META_PATH) if META_PATH.exists() else {}
    payload = {
        "job_id": "vocab:sonoma-14.4.1",
        "status": "ok",
        "tier": "bedrock",
        "host": meta.get("os", {}),
        "inputs": [to_repo_relative(LIB_PATH, ROOT)],
        "outputs": [to_repo_relative(OPS_MAP, ROOT), to_repo_relative(FILTERS_MAP, ROOT)],
        "counts": {"ops": len(op_names), "filters": len(filter_names)},
        "tags": ["vocab", "host:sonoma-14.4.1", "smoke"],
    }
    STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATUS_PATH.write_text(json.dumps(payload, indent=2))
    return {
        "status": "ok",
        "tier": "bedrock",
        "outputs": [
            to_repo_relative(OPS_MAP, ROOT),
            to_repo_relative(FILTERS_MAP, ROOT),
            to_repo_relative(STATUS_PATH, ROOT),
        ],
        "metrics": payload["counts"],
        "host": payload["host"],
        "notes": "Verified libsandbox vocab against canonical mappings.",
    }


registry.register(
    ValidationJob(
        id="vocab:sonoma-14.4.1",
        inputs=[to_repo_relative(LIB_PATH, ROOT)],
        outputs=[to_repo_relative(OPS_MAP, ROOT), to_repo_relative(FILTERS_MAP, ROOT), to_repo_relative(STATUS_PATH, ROOT)],
        tags=["vocab", "host:sonoma-14.4.1", "smoke", "golden"],
        description="Harvest and verify libsandbox vocab against canonical mappings.",
        example_command="python -m book.graph.concepts.validation --id vocab:sonoma-14.4.1",
        runner=run_vocab_harvest_job,
    )
)
