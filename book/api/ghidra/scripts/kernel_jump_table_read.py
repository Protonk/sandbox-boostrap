#@category Sandbox
"""
Read a signed-32 jump table and resolve target addresses.
Args: <out_dir> <build_id> <table_addr_hex> <base_addr_hex> <count> [alt_base_hex] [alt_label]

Outputs: <out_dir>/jump_table_entries.json

Notes:
- Jump table entries are signed 32-bit offsets relative to the base.
- alt_base is useful when tables are indexed from a different anchor.
"""

import json
import os
import traceback

from ghidra_bootstrap import io_utils, scan_utils

from ghidra.program.model.mem import MemoryAccessException

_RUN_CALLED = False


def _ensure_out_dir(path):
    return io_utils.ensure_out_dir(path)

def _parse_int(token, default=None):
    try:
        return int(token, 0)
    except Exception:
        return default


def _parse_hex_addr(token):
    return scan_utils.parse_hex(token)


def run():
    global _RUN_CALLED
    if _RUN_CALLED:
        return
    _RUN_CALLED = True
    out_dir = None
    try:
        args = getScriptArgs()
        if len(args) < 5:
            print("usage: kernel_jump_table_read.py <out_dir> <build_id> <table_addr_hex> <base_addr_hex> <count> [alt_base_hex] [alt_label]")
            return
        out_dir = args[0]
        build_id = args[1]
        table_addr = _parse_hex_addr(args[2])
        base_addr = _parse_hex_addr(args[3])
        count = _parse_int(args[4], 0)
        alt_base = None
        alt_label = None
        if len(args) > 5:
            alt_base = _parse_hex_addr(args[5])
            alt_label = str(args[6]) if len(args) > 6 else "alt"
        if table_addr is None or base_addr is None:
            raise ValueError("Invalid table/base address")

        _ensure_out_dir(out_dir)
        mem = currentProgram.getMemory()
        func_mgr = currentProgram.getFunctionManager()
        addr_factory = currentProgram.getAddressFactory()
        addr_space = addr_factory.getDefaultAddressSpace()

        entries = []
        for idx in range(count):
            entry_addr_val = table_addr + (idx * 4)
            entry_addr = addr_space.getAddress(scan_utils.format_address(entry_addr_val))
            try:
                raw = mem.getInt(entry_addr)
            except MemoryAccessException:
                break
            except Exception:
                break
            raw_u32 = raw & 0xFFFFFFFF
            offset = raw_u32
            if raw_u32 & 0x80000000:
                # Interpret entries as signed 32-bit offsets.
                offset = raw_u32 - 0x100000000
            target_val = (base_addr + offset) & ((1 << 64) - 1)
            target_addr = addr_space.getAddress(scan_utils.format_address(target_val))
            func = func_mgr.getFunctionAt(target_addr)
            entry = {
                "index": idx,
                "entry_addr": scan_utils.format_address(entry_addr_val),
                "offset": offset,
                "offset_u32": raw_u32,
                "target": scan_utils.format_address(target_val),
                "target_function": func.getName() if func else None,
            }
            if alt_base is not None:
                # alt_base lets callers compare two candidate anchors quickly.
                alt_target = (alt_base + offset) & ((1 << 64) - 1)
                alt_addr = addr_space.getAddress(scan_utils.format_address(alt_target))
                alt_func = func_mgr.getFunctionAt(alt_addr)
                entry["alt_base"] = scan_utils.format_address(alt_base)
                entry["alt_target"] = scan_utils.format_address(alt_target)
                entry["alt_target_function"] = alt_func.getName() if alt_func else None
                entry["alt_label"] = alt_label
            entries.append(entry)

        meta = {
            "build_id": build_id,
            "program": currentProgram.getName(),
            "table_addr": scan_utils.format_address(table_addr),
            "base_addr": scan_utils.format_address(base_addr),
            "count": count,
            "entry_count": len(entries),
        }
        if alt_base is not None:
            meta["alt_base"] = scan_utils.format_address(alt_base)
            meta["alt_label"] = alt_label
        with open(os.path.join(out_dir, "jump_table_entries.json"), "w") as f:
            json.dump({"meta": meta, "entries": entries}, f, indent=2, sort_keys=True)
        print("kernel_jump_table_read: wrote %d entries" % len(entries))
    except Exception:
        if out_dir:
            try:
                _ensure_out_dir(out_dir)
                with open(os.path.join(out_dir, "error.log"), "w") as err:
                    traceback.print_exc(file=err)
            except Exception:
                pass
        traceback.print_exc()


run()
