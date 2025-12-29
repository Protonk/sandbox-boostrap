#@category Sandbox
"""
Search instructions for a given immediate (scalar) value.
Args: <out_dir> <build_id> <imm_hex> [all]
Scans sandbox blocks by default; include "all" to scan entire program.

Outputs: dumps/ghidra/out/<build>/kernel-imm-search/<imm_hex>.json (plus script.log).
Pitfalls: ensure ARM64 processor import so immediate widths are parsed correctly; function recovery not required but helps triage.
"""

import json
import os
import traceback

from ghidra_bootstrap import scan_utils

from ghidra.program.model.address import AddressSet

_RUN_CALLED = False


def _ensure_out_dir(path):
    if not os.path.isdir(path):
        os.makedirs(path)


def _sandbox_blocks():
    mem = currentProgram.getMemory()
    blocks = []
    for blk in mem.getBlocks():
        name = blk.getName() or ""
        if "sandbox" in name.lower():
            blocks.append(blk)
    if blocks:
        return blocks
    return list(mem.getBlocks())


def _block_set(blocks):
    aset = AddressSet()
    for blk in blocks:
        aset.add(blk.getStart(), blk.getEnd())
    return aset


def run():
    global _RUN_CALLED
    if _RUN_CALLED:
        return
    _RUN_CALLED = True
    out_dir = None
    try:
        args = getScriptArgs()
        if len(args) < 3:
            print("usage: kernel_imm_search.py <out_dir> <build_id> <imm_hex> [all]")
            return
        out_dir = args[0]
        build_id = args[1]
        imm = int(args[2], 16)
        scan_all = False
        if len(args) > 3 and args[3].lower() == "all":
            scan_all = True
        _ensure_out_dir(out_dir)
        listing = currentProgram.getListing()
        func_mgr = currentProgram.getFunctionManager()
        blocks = list(currentProgram.getMemory().getBlocks()) if scan_all else _sandbox_blocks()
        addr_set = _block_set(blocks)
        hits = []
        instr_iter = listing.getInstructions(addr_set, True)
        while instr_iter.hasNext() and not monitor.isCancelled():
            instr = instr_iter.next()
            for op_index in range(instr.getNumOperands()):
                objs = instr.getOpObjects(op_index)
                for obj in objs:
                    try:
                        val = int(obj)
                    except Exception:
                        continue
                    if val == imm or (imm > (1 << 63) and (val & ((1 << 64) - 1)) == imm):
                        addr = instr.getAddress()
                        func = func_mgr.getFunctionContaining(addr)
                        hits.append(
                            {
                                "address": scan_utils.format_address(addr.getOffset()),
                                "function": func.getName() if func else None,
                                "mnemonic": instr.getMnemonicString(),
                                "inst": str(instr),
                            }
                        )
                        break
        block_meta = [{"name": b.getName(), "start": scan_utils.format_address(b.getStart().getOffset()), "end": scan_utils.format_address(b.getEnd().getOffset())} for b in blocks]
        meta = {
            "build_id": build_id,
            "program": currentProgram.getName(),
            "imm": scan_utils.format_address(imm),
            "hit_count": len(hits),
            "scan_all_blocks": scan_all,
            "block_filter": block_meta,
        }
        with open(os.path.join(out_dir, "imm_search.json"), "w") as f:
            json.dump({"meta": meta, "hits": hits}, f, indent=2, sort_keys=True)
        print("kernel_imm_search: %d hits for %s" % (len(hits), scan_utils.format_address(imm)))
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
from ghidra.program.model.address import AddressSet
