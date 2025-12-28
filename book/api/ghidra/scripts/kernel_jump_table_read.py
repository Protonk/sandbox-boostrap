#@category Sandbox
"""
Read a signed-32 jump table and resolve target addresses.
Args: <out_dir> <build_id> <table_addr_hex> <base_addr_hex> <count> [alt_base_hex] [alt_label]

Outputs: <out_dir>/jump_table_entries.json
"""

import json
import os
import traceback

from ghidra.program.model.mem import MemoryAccessException

_RUN_CALLED = False


def _ensure_out_dir(path):
    if not os.path.isdir(path):
        os.makedirs(path)


def _parse_int(token, default=None):
    try:
        return int(token, 0)
    except Exception:
        return default


def _parse_hex_addr(token):
    text = token.strip().lower()
    if text.startswith("0x-"):
        text = "-0x" + text[3:]
    val = _parse_int(text)
    if val is None:
        return None
    if val < 0:
        val = (1 << 64) + val
    return val


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
            entry_addr = addr_space.getAddress("0x%x" % entry_addr_val)
            try:
                raw = mem.getInt(entry_addr)
            except MemoryAccessException:
                break
            except Exception:
                break
            raw_u32 = raw & 0xFFFFFFFF
            offset = raw_u32
            if raw_u32 & 0x80000000:
                offset = raw_u32 - 0x100000000
            target_val = (base_addr + offset) & ((1 << 64) - 1)
            target_addr = addr_space.getAddress("0x%x" % target_val)
            func = func_mgr.getFunctionAt(target_addr)
            entry = {
                "index": idx,
                "entry_addr": "0x%x" % entry_addr_val,
                "offset": offset,
                "offset_u32": raw_u32,
                "target": "0x%x" % target_val,
                "target_function": func.getName() if func else None,
            }
            if alt_base is not None:
                alt_target = (alt_base + offset) & ((1 << 64) - 1)
                alt_addr = addr_space.getAddress("0x%x" % alt_target)
                alt_func = func_mgr.getFunctionAt(alt_addr)
                entry["alt_base"] = "0x%x" % alt_base
                entry["alt_target"] = "0x%x" % alt_target
                entry["alt_target_function"] = alt_func.getName() if alt_func else None
                entry["alt_label"] = alt_label
            entries.append(entry)

        meta = {
            "build_id": build_id,
            "program": currentProgram.getName(),
            "table_addr": "0x%x" % table_addr,
            "base_addr": "0x%x" % base_addr,
            "count": count,
            "entry_count": len(entries),
        }
        if alt_base is not None:
            meta["alt_base"] = "0x%x" % alt_base
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
