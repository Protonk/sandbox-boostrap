#@category Sandbox
"""
Dump a window of pointer table entries around a target address.

Args (from scaffold/manual): <out_dir> <build_id> <addr_hex> [entries] [stride] [mode]
  entries: total number of entries to dump (default: 64). In "auto" mode this is a max cap.
  stride: byte stride between entries (default: 8).
  mode: "center" (default) treats addr as center; "base" treats addr as start.
        "auto" expands outward until a non-pointer or block change is seen.

Outputs: <out_dir>/pointer_window.json
"""

import json
import os
import traceback

from ghidra_bootstrap import scan_utils


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
    return scan_utils.parse_hex(token)


def _hex_u64(value):
    return scan_utils.format_address(value)


def _read_entry(entry_addr, memory, func_mgr, addr_space):
    entry_addr_obj = addr_space.getAddress(scan_utils.format_address(entry_addr))
    entry_block = memory.getBlock(entry_addr_obj)
    if not entry_block:
        return None, None, None, None, "no_entry_block"
    try:
        raw = memory.getLong(entry_addr_obj)
    except Exception:
        return entry_block, None, None, None, "read_failed"
    value_s = int(raw)
    value_u = value_s if value_s >= 0 else (1 << 64) + value_s
    if value_u == 0:
        return entry_block, value_u, None, None, "null_value"
    target_block = None
    target_func = None
    try:
        tgt_addr = addr_space.getAddress(scan_utils.format_address(value_u))
        target_block = memory.getBlock(tgt_addr)
        func = func_mgr.getFunctionContaining(tgt_addr)
        target_func = func.getName() if func else None
    except Exception:
        target_block = None
    if not target_block:
        return entry_block, value_u, None, target_func, "no_target_block"
    return entry_block, value_u, target_block, target_func, None


def run():
    global _RUN_CALLED
    if _RUN_CALLED:
        return
    _RUN_CALLED = True
    out_dir = None
    try:
        args = getScriptArgs()
        if len(args) < 3:
            print("usage: kernel_pointer_table_window.py <out_dir> <build_id> <addr_hex> [entries] [stride] [mode]")
            return
        out_dir = args[0]
        build_id = args[1]
        addr = _parse_hex_addr(args[2])
        if addr is None:
            raise ValueError("Invalid address: %s" % args[2])
        entries = _parse_int(args[3], 64) if len(args) > 3 else 64
        stride = _parse_int(args[4], 8) if len(args) > 4 else 8
        mode = args[5].lower() if len(args) > 5 else "center"

        _ensure_out_dir(out_dir)
        memory = currentProgram.getMemory()
        func_mgr = currentProgram.getFunctionManager()
        addr_factory = currentProgram.getAddressFactory()
        addr_space = addr_factory.getDefaultAddressSpace()

        rows = []
        stop_back = None
        stop_forward = None
        entry_block_name = None
        target_block_name = None

        if mode == "auto":
            entry_block, value_u, target_block, target_func, reason = _read_entry(addr, memory, func_mgr, addr_space)
            if reason:
                raise ValueError("auto mode failed at center: %s" % reason)
            entry_block_name = entry_block.getName() if entry_block else None
            target_block_name = target_block.getName() if target_block else None
            center_row = {
                "index": 0,
                "entry_addr": _hex_u64(addr),
                "value": _hex_u64(value_u),
                "value_signed": value_u if value_u is None else (value_u if value_u < (1 << 63) else value_u - (1 << 64)),
                "target_block": target_block_name,
                "target_function": target_func,
            }

            back_rows = []
            forward_rows = []
            remaining = entries - 1 if entries > 0 else 0
            # scan backward
            step = -stride
            cursor = addr + step
            while cursor >= 0 and (entries <= 0 or len(back_rows) + len(forward_rows) < remaining):
                entry_block, value_u, target_block, target_func, reason = _read_entry(cursor, memory, func_mgr, addr_space)
                if reason:
                    stop_back = reason
                    break
                if entry_block_name and entry_block.getName() != entry_block_name:
                    stop_back = "entry_block_change"
                    break
                if target_block_name and target_block and target_block.getName() != target_block_name:
                    stop_back = "target_block_change"
                    break
                back_rows.append(
                    {
                        "index": 0,
                        "entry_addr": _hex_u64(cursor),
                        "value": _hex_u64(value_u),
                        "value_signed": value_u if value_u < (1 << 63) else value_u - (1 << 64),
                        "target_block": target_block.getName() if target_block else None,
                        "target_function": target_func,
                    }
                )
                cursor += step

            # scan forward
            step = stride
            cursor = addr + step
            while entries <= 0 or len(back_rows) + len(forward_rows) < remaining:
                entry_block, value_u, target_block, target_func, reason = _read_entry(cursor, memory, func_mgr, addr_space)
                if reason:
                    stop_forward = reason
                    break
                if entry_block_name and entry_block.getName() != entry_block_name:
                    stop_forward = "entry_block_change"
                    break
                if target_block_name and target_block and target_block.getName() != target_block_name:
                    stop_forward = "target_block_change"
                    break
                forward_rows.append(
                    {
                        "index": 0,
                        "entry_addr": _hex_u64(cursor),
                        "value": _hex_u64(value_u),
                        "value_signed": value_u if value_u < (1 << 63) else value_u - (1 << 64),
                        "target_block": target_block.getName() if target_block else None,
                        "target_function": target_func,
                    }
                )
                cursor += step

            rows = list(reversed(back_rows)) + [center_row] + forward_rows
            start = _parse_hex_addr(rows[0]["entry_addr"]) if rows else addr
        else:
            if mode == "base":
                start = addr
            else:
                start = addr - (entries // 2) * stride
            if start < 0:
                start = 0
            for i in range(entries):
                entry_addr = start + (i * stride)
                entry_block, value_u, target_block, target_func, _ = _read_entry(entry_addr, memory, func_mgr, addr_space)
                value_s = None
                if value_u is not None:
                    value_s = value_u if value_u < (1 << 63) else value_u - (1 << 64)
                rows.append(
                    {
                        "index": i,
                        "entry_addr": _hex_u64(entry_addr),
                        "value": _hex_u64(value_u),
                        "value_signed": value_s,
                        "target_block": target_block.getName() if target_block else None,
                        "target_function": target_func,
                    }
                )

        meta = {
            "build_id": build_id,
            "program": currentProgram.getName(),
            "addr": _hex_u64(addr),
            "entries": entries,
            "stride": stride,
            "mode": mode,
            "start": _hex_u64(start),
            "entry_block": entry_block_name,
            "target_block": target_block_name,
            "stop_back": stop_back,
            "stop_forward": stop_forward,
        }
        with open(os.path.join(out_dir, "pointer_window.json"), "w") as fh:
            json.dump({"meta": meta, "rows": rows}, fh, indent=2, sort_keys=True)
        print("kernel_pointer_table_window: wrote %d entries" % len(rows))
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
