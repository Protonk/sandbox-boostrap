#@category Sandbox
"""
Scan sandbox kext data segments for mac_policy_conf-like structs.

Args: <out_dir> [build_id] [any-ptr]
Template (64-bit, permissive):
  slot0: ptr -> name string (nullable)
  slot1: ptr -> fullname string (nullable)
  slot2: ptr -> labelnames (nullable)
  slot3: u32 labelname_count (<= MAX_LABELNAME_COUNT)
  slot4: ptr -> ops (nullable)
  slot5: u32 loadtime_flags
  slot6: ptr -> field_off / label slot (nullable)
  slot7: u32 runtime_flags
  slot8: optional list pointer
  slot9: optional data pointer

Hard filters live in-pointer/segment checks and small ints; content checks are soft and emitted for offline ranking.
Emits mac_policy_conf_candidates.json with meta + candidates.
"""

import json
import os
import string
import traceback

from ghidra_bootstrap import scan_utils

SCAN_SLOTS = 10  # cover core mac_policy_conf plus common list/data extras
MAX_STR_LEN = 128
MAX_LABELNAME_COUNT = 32


def _ensure(path):
    if not os.path.isdir(path):
        os.makedirs(path)


def _read_qword(mem, factory, offset):
    try:
        addr = factory.getDefaultAddressSpace().getAddress(scan_utils.format_address(offset))
        val = mem.getLong(addr)
        return addr, val & 0xFFFFFFFFFFFFFFFF
    except Exception:
        return None, None


def _read_ascii(mem, ptr_addr, max_len=MAX_STR_LEN):
    try:
        blk = mem.getBlock(ptr_addr)
        if blk is None or not blk.isInitialized():
            return None
        buf = bytearray()
        for _ in range(max_len):
            b = mem.getByte(ptr_addr)
            if b == 0:
                break
            buf.append(b & 0xFF)
            ptr_addr = ptr_addr.add(1)
        else:
            return None
        if not buf:
            return None
        text = buf.decode("ascii", errors="ignore")
        if not text:
            return None
        if any(ch not in string.printable for ch in text):
            return None
        return text
    except Exception:
        return None


def _valid_ptr(ptr, ranges, min_u, max_u, allow_any=False):
    if ptr == 0:
        return True
    if ptr % 8 != 0:
        return False
    if allow_any:
        return True
    if ptr < min_u or ptr > max_u:
        return False
    for lo, hi, _ in ranges:
        if lo <= ptr <= hi:
            return True
    return False


def _block_list():
    mem = currentProgram.getMemory()
    return [blk for blk in mem.getBlocks() if blk.isInitialized() and blk.isLoaded()]


def _block_ranges(blocks):
    ranges = []
    min_u = None
    max_u = None
    mask = 0xFFFFFFFFFFFFFFFF
    for blk in blocks:
        start = blk.getStart().getOffset() & mask
        end = blk.getEnd().getOffset() & mask
        lo = min(start, end)
        hi = max(start, end)
        min_u = lo if min_u is None else min(min_u, lo)
        max_u = hi if max_u is None else max(max_u, hi)
        ranges.append((lo, hi, blk))
    return ranges, min_u or 0, max_u or 0


def _block_name(addr, memory):
    blk = memory.getBlock(addr)
    return blk.getName() if blk else None


def _is_exec_or_const(block_name):
    if not block_name:
        return False
    name = block_name.lower()
    return "__text" in name or "__const" in name or "text" in name or "const" in name


def scan(allow_any_ptr=False):
    memory = currentProgram.getMemory()
    factory = currentProgram.getAddressFactory()
    candidates = []
    blocks = _block_list()
    ranges, min_u, max_u = _block_ranges(blocks)
    bytes_scanned = 0
    probe_points = 0

    for blk in blocks:
        name = blk.getName() or ""
        if "__data" not in name.lower() and "__const" not in name.lower():
            continue
        bytes_scanned += blk.getSize()
        addr = blk.getStart()
        end = blk.getEnd()
        while addr.add(SCAN_SLOTS * 8) <= end:
            probe_points += 1
            base_off = addr.getOffset()
            slots = []
            ok = True
            for i in range(SCAN_SLOTS):
                a, v = _read_qword(memory, factory, base_off + i * 8)
                if a is None:
                    ok = False
                    break
                slots.append((a, v))
            if not ok:
                addr = addr.add(8)
                continue

            name_ptr = slots[0][1]
            fullname_ptr = slots[1][1]
            labelnames_ptr = slots[2][1]
            labelname_count_raw = slots[3][1]
            labelname_count = labelname_count_raw & 0xFFFFFFFF
            ops_ptr = slots[4][1]
            loadtime_flags_raw = slots[5][1]
            loadtime_flags = loadtime_flags_raw & 0xFFFFFFFF
            field_slot = slots[6][1]
            runtime_flags_raw = slots[7][1]
            runtime_flags = runtime_flags_raw & 0xFFFFFFFF
            extra0 = slots[8][1]
            extra1 = slots[9][1]

            # Hard constraints: addressable slots, small labelname_count, pointer-ish fields either NULL or inside this program.
            if labelname_count > MAX_LABELNAME_COUNT:
                addr = addr.add(8)
                continue
            if not (
                _valid_ptr(name_ptr, ranges, min_u, max_u, allow_any_ptr)
                and _valid_ptr(fullname_ptr, ranges, min_u, max_u, allow_any_ptr)
                and _valid_ptr(labelnames_ptr, ranges, min_u, max_u, allow_any_ptr)
                and _valid_ptr(ops_ptr, ranges, min_u, max_u, allow_any_ptr)
                and _valid_ptr(field_slot, ranges, min_u, max_u, allow_any_ptr)
                and _valid_ptr(extra0, ranges, min_u, max_u, allow_any_ptr)
                and _valid_ptr(extra1, ranges, min_u, max_u, allow_any_ptr)
            ):
                addr = addr.add(8)
                continue

            # Soft signals gathered but not required.
            name_str = None
            fullname_str = None
            if name_ptr:
                nptr_addr = factory.getDefaultAddressSpace().getAddress(scan_utils.format_address(name_ptr))
                name_str = _read_ascii(memory, nptr_addr)
                if name_str is None:
                    addr = addr.add(8)
                    continue
            if fullname_ptr:
                fptr_addr = factory.getDefaultAddressSpace().getAddress(scan_utils.format_address(fullname_ptr))
                fullname_str = _read_ascii(memory, fptr_addr)
                if fullname_str is None:
                    addr = addr.add(8)
                    continue
            ops_block = None
            if ops_ptr:
                ops_addr = factory.getDefaultAddressSpace().getAddress(scan_utils.format_address(ops_ptr))
                ops_block = _block_name(ops_addr, memory)

            soft_score = 0
            soft_flags = {}
            if name_str:
                soft_score += 1
                soft_flags["name_present"] = True
            if fullname_str:
                soft_score += 1
                soft_flags["fullname_present"] = True
            if ops_ptr:
                soft_score += 1
                soft_flags["ops_nonnull"] = True
            if labelnames_ptr:
                soft_flags["labelnames_nonnull"] = True
            if loadtime_flags in (0x2, 0x4, 0x6):
                soft_score += 1
                soft_flags["loadtime_flag_hint"] = scan_utils.format_address(loadtime_flags)

            candidates.append(
                {
                    "address": scan_utils.format_address(base_off),
                    "segment": name,
                    "slots": {
                        "name": scan_utils.format_address(name_ptr),
                        "fullname": scan_utils.format_address(fullname_ptr),
                        "labelnames": scan_utils.format_address(labelnames_ptr),
                        "labelname_count": labelname_count,
                        "ops": scan_utils.format_address(ops_ptr),
                        "loadtime_flags": scan_utils.format_address(loadtime_flags),
                        "field_or_label_slot": scan_utils.format_address(field_slot),
                        "runtime_flags": scan_utils.format_address(runtime_flags),
                        "extra0": scan_utils.format_address(extra0),
                        "extra1": scan_utils.format_address(extra1),
                    },
                    "string_values": {"name": name_str, "fullname": fullname_str},
                    "ops_block": ops_block,
                    "soft_score": soft_score,
                    "soft_flags": soft_flags,
                }
            )
            addr = addr.add(8)
        # end block walk
    return candidates, blocks, {"bytes_scanned": bytes_scanned, "probe_points": probe_points}


def run():
    out_dir = None
    try:
        args = getScriptArgs()
        if len(args) < 1:
            print("usage: sandbox_kext_conf_scan.py <out_dir> [build_id]")
            return
        out_dir = args[0]
        build_id = args[1] if len(args) > 1 else ""
        allow_any = len(args) > 2 and args[2] == "any-ptr"
        _ensure(out_dir)
        cands, blocks, scan_stats = scan(allow_any_ptr=allow_any)
        block_meta = [
            {
                "name": blk.getName(),
                "start": scan_utils.format_address(blk.getStart().getOffset()),
                "end": scan_utils.format_address(blk.getEnd().getOffset()),
            }
            for blk in blocks
        ]
        meta = {
            "build_id": build_id,
            "program": currentProgram.getName(),
            "block_filter": block_meta,
            "candidate_count": len(cands),
            "scan_slots": SCAN_SLOTS,
            "max_labelname_count": MAX_LABELNAME_COUNT,
            "probe_points": scan_stats.get("probe_points", 0),
            "bytes_scanned": scan_stats.get("bytes_scanned", 0),
            "allow_any_ptr": allow_any,
        }
        with open(os.path.join(out_dir, "mac_policy_conf_candidates.json"), "w") as f:
            json.dump({"meta": meta, "candidates": cands}, f, indent=2, sort_keys=True)
        print("sandbox_kext_conf_scan: wrote %d candidates" % len(cands))
    except Exception:
        if out_dir:
            try:
                _ensure(out_dir)
                with open(os.path.join(out_dir, "error.log"), "w") as err:
                    traceback.print_exc(file=err)
            except Exception:
                pass
        traceback.print_exc()


if not os.environ.get("GHIDRA_SKIP_AUTORUN"):
    run()
