#@category Sandbox
"""
Surface pointer-table candidates inside com.apple.security.sandbox segments.

Args (from scaffold): <out_dir> <build_id>
Outputs: book/evidence/dumps/ghidra/out/<build>/kernel-op-table/op_table_candidates.json (plus script.log).

Heuristic:
- Scan for contiguous pointer runs that mostly target functions (signed addresses handled).
- Restrict to sandbox blocks when available; otherwise scan the full program.

Pitfalls:
- Use a correct processor import so pointer size and address sign-extension are correct.
- With --no-analysis you still get memory blocks, but function detection may be weaker.

Notes:
- Candidate tables are long runs of function pointers; shorter runs are ignored as noise.
- Pointers are sign-extended by Ghidra; normalization is required to stay within block bounds.
"""

import json
import os
import traceback

from ghidra_bootstrap import block_utils, io_utils, scan_utils

from ghidra.program.model.address import AddressSet
from ghidra.program.model.mem import MemoryAccessException

_RUN_CALLED = False


def _ensure_out_dir(path):
    return io_utils.ensure_out_dir(path)

def _sandbox_blocks():
    return block_utils.sandbox_blocks(program=currentProgram)

def _block_set(blocks):
    return block_utils.block_set(blocks)

def _read_pointer(mem, addr, ptr_size, addr_factory):
    try:
        raw = mem.getLong(addr) if ptr_size == 8 else mem.getInt(addr)
    except MemoryAccessException:
        return None
    except Exception:
        return None
    mask = (1 << (ptr_size * 8)) - 1
    value = raw & mask
    if value == 0:
        return 0
    signed_value = value
    sign_bit = 1 << (ptr_size * 8 - 1)
    if value & sign_bit:
        signed_value = value - (1 << (ptr_size * 8))
    target = addr_factory.getDefaultAddressSpace().getAddress(signed_value)
    if target is None or not mem.contains(target):
        return None
    return target


def _scan_block_for_tables(block, ptr_size, func_mgr, addr_factory):
    mem = currentProgram.getMemory()
    start = block.getStart()
    end = block.getEnd().subtract(ptr_size - 1)
    tables = []
    addr = start
    # Require a minimum run length to avoid false positives from small pointer arrays.
    min_len = 32
    while addr.compareTo(end) <= 0 and not monitor.isCancelled():
        target = _read_pointer(mem, addr, ptr_size, addr_factory)
        if target and func_mgr.getFunctionAt(target):
            run = []
            run_addr = addr
            while run_addr.compareTo(end) <= 0 and not monitor.isCancelled():
                ptr_target = _read_pointer(mem, run_addr, ptr_size, addr_factory)
                if ptr_target is None:
                    break
                func = func_mgr.getFunctionAt(ptr_target) if ptr_target else None
                run.append(
                    {
                        "offset": scan_utils.format_address(run_addr.getOffset()),
                        "target": scan_utils.format_address(ptr_target.getOffset()) if ptr_target else None,
                        "function": func.getName() if func else None,
                    }
                )
                run_addr = run_addr.add(ptr_size)
            if len(run) >= min_len:
                truncated = False
                # Cap table size to keep JSON outputs bounded.
                max_entries = 512
                if len(run) > max_entries:
                    run = run[:max_entries]
                    truncated = True
                tables.append(
                    {
                        "block": block.getName(),
                        "start": scan_utils.format_address(addr.getOffset()),
                        "length": len(run),
                        "truncated": truncated,
                        "entries": run,
                    }
                )
                addr = run_addr
            else:
                addr = addr.add(ptr_size)
        else:
            addr = addr.add(ptr_size)
    return tables


def run():
    global _RUN_CALLED
    if _RUN_CALLED:
        return
    _RUN_CALLED = True
    try:
        args = getScriptArgs()
        if len(args) < 1:
            print("usage: kernel_op_table.py <out_dir> [build_id] [all]")
            return
        out_dir = args[0]
        build_id = args[1] if len(args) > 1 else ""
        scan_all = False
        if len(args) > 2 and args[2].lower() == "all":
            scan_all = True
        print("kernel_op_table: starting for build %s -> %s" % (build_id, out_dir))

        _ensure_out_dir(out_dir)
        blocks = list(currentProgram.getMemory().getBlocks()) if scan_all else _sandbox_blocks()
        addr_set = _block_set(blocks)
        block_meta = [
            {
                "name": blk.getName(),
                "start": scan_utils.format_address(blk.getStart().getOffset()),
                "end": scan_utils.format_address(blk.getEnd().getOffset()),
            }
            for blk in blocks
        ]

        ptr_size = currentProgram.getDefaultPointerSize()
        func_mgr = currentProgram.getFunctionManager()
        addr_factory = currentProgram.getAddressFactory()

        candidates = []
        for blk in blocks:
            candidates.extend(_scan_block_for_tables(blk, ptr_size, func_mgr, addr_factory))
            if monitor.isCancelled():
                break

        meta = {
            "build_id": build_id,
            "program": currentProgram.getName(),
            "block_filter": block_meta,
            "pointer_size": ptr_size,
            "candidate_count": len(candidates),
            "scan_all_blocks": scan_all,
        }
        with open(os.path.join(out_dir, "op_table_candidates.json"), "w") as f:
            json.dump({"meta": meta, "candidates": candidates}, f, indent=2, sort_keys=True)

        print("kernel_op_table: %d pointer-table candidates written to %s" % (len(candidates), out_dir))
    except Exception:
        if "out_dir" in locals() and out_dir:
            try:
                _ensure_out_dir(out_dir)
                with open(os.path.join(out_dir, "error.log"), "w") as err:
                    traceback.print_exc(file=err)
            except Exception:
                pass
        traceback.print_exc()


run()
