#@category Sandbox
"""
Scan memory for pointer values equal to a target address.
Args: <out_dir> <build_id> <target_hex> [stride] [max_hits] [all]

By default scans non-executable blocks; include "all" to scan every block.
Outputs: <out_dir>/pointer_value_hits.json
"""

import json
import os
import traceback

from ghidra_bootstrap import scan_utils

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
    return scan_utils.parse_hex(token)


def _iter_blocks(scan_all):
    mem = currentProgram.getMemory()
    for blk in mem.getBlocks():
        if not scan_all and blk.isExecute():
            continue
        yield blk


def run():
    global _RUN_CALLED
    if _RUN_CALLED:
        return
    _RUN_CALLED = True
    out_dir = None
    try:
        args = getScriptArgs()
        if len(args) < 3:
            print("usage: kernel_pointer_value_scan.py <out_dir> <build_id> <target_hex> [stride] [max_hits] [all]")
            return
        out_dir = args[0]
        build_id = args[1]
        target = _parse_hex_addr(args[2])
        if target is None:
            raise ValueError("Invalid target address: %s" % args[2])
        stride = _parse_int(args[3], 8) if len(args) > 3 else 8
        max_hits = _parse_int(args[4], 1024) if len(args) > 4 else 1024
        scan_all = False
        if len(args) > 5 and str(args[5]).lower() == "all":
            scan_all = True

        _ensure_out_dir(out_dir)
        mem = currentProgram.getMemory()
        func_mgr = currentProgram.getFunctionManager()
        addr_factory = currentProgram.getAddressFactory()
        addr_space = addr_factory.getDefaultAddressSpace()

        hits = []
        scanned = 0
        for blk in _iter_blocks(scan_all):
            start = blk.getStart()
            end = blk.getEnd().subtract(7)
            addr = start
            while addr.compareTo(end) <= 0 and not monitor.isCancelled():
                try:
                    raw = mem.getLong(addr)
                except MemoryAccessException:
                    addr = addr.add(stride)
                    continue
                except Exception:
                    addr = addr.add(stride)
                    continue
                scanned += 1
                val_u = raw if raw >= 0 else (1 << 64) + raw
                if val_u == target:
                    tgt_addr = addr_space.getAddress(scan_utils.format_address(val_u))
                    tgt_func = func_mgr.getFunctionAt(tgt_addr)
                    hits.append(
                        {
                            "entry_addr": scan_utils.format_address(addr.getOffset()),
                            "block": blk.getName(),
                            "value": scan_utils.format_address(val_u),
                            "target_function": tgt_func.getName() if tgt_func else None,
                        }
                    )
                    if max_hits and len(hits) >= max_hits:
                        break
                addr = addr.add(stride)
            if max_hits and len(hits) >= max_hits:
                break

        meta = {
            "build_id": build_id,
            "program": currentProgram.getName(),
            "target": scan_utils.format_address(target),
            "stride": stride,
            "scan_all_blocks": scan_all,
            "max_hits": max_hits,
            "hit_count": len(hits),
            "scanned_slots": scanned,
        }
        with open(os.path.join(out_dir, "pointer_value_hits.json"), "w") as f:
            json.dump({"meta": meta, "hits": hits}, f, indent=2, sort_keys=True)
        print("kernel_pointer_value_scan: %d hits" % len(hits))
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
