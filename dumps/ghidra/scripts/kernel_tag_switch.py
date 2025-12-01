#@category Sandbox
"""
Surface candidate dispatcher functions by counting computed jumps per function.
Outputs a ranking under dumps/ghidra/out/<build>/kernel-tag-switch/ to speed manual tag-switch identification.
"""

import json
import os
import traceback

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


def _count_computed_jumps(func, listing):
    computed = 0
    jump_like = 0
    inst_iter = listing.getInstructions(func.getBody(), True)
    while inst_iter.hasNext() and not monitor.isCancelled():
        inst = inst_iter.next()
        flow = inst.getFlowType()
        if flow.isJump() and flow.isComputed():
            computed += 1
            if flow.isIndirect() or flow.isUnConditional():
                jump_like += 1
    return computed, jump_like


def run():
    global _RUN_CALLED
    if _RUN_CALLED:
        return
    _RUN_CALLED = True
    try:
        args = getScriptArgs()
        if len(args) < 1:
            print("usage: kernel_tag_switch.py <out_dir> [build_id]")
            return
        out_dir = args[0]
        build_id = args[1] if len(args) > 1 else ""
        print("kernel_tag_switch: starting for build %s -> %s" % (build_id, out_dir))

        _ensure_out_dir(out_dir)
        blocks = _sandbox_blocks()
        addr_set = _block_set(blocks)
        block_meta = [
            {
                "name": blk.getName(),
                "start": "0x%x" % blk.getStart().getOffset(),
                "end": "0x%x" % blk.getEnd().getOffset(),
            }
            for blk in blocks
        ]

        fm = currentProgram.getFunctionManager()
        listing = currentProgram.getListing()
        candidates = []

        func_iter = fm.getFunctions(True)
        while func_iter.hasNext() and not monitor.isCancelled():
            func = func_iter.next()
            entry = func.getEntryPoint()
            if not addr_set.contains(entry):
                continue
            computed, jump_like = _count_computed_jumps(func, listing)
            if computed == 0:
                continue
            candidates.append(
                {
                    "name": func.getName(),
                    "address": "0x%x" % entry.getOffset(),
                    "computed_jumps": computed,
                    "jump_like": jump_like,
                    "size": func.getBody().getNumAddresses(),
                    "calling_convention": func.getCallingConventionName(),
                }
            )

        candidates.sort(key=lambda c: (c["computed_jumps"], c["size"]), reverse=True)
        meta = {
            "build_id": build_id,
            "program": currentProgram.getName(),
            "block_filter": block_meta,
            "candidate_count": len(candidates),
        }
        with open(os.path.join(out_dir, "switch_candidates.json"), "w") as f:
            json.dump({"meta": meta, "candidates": candidates}, f, indent=2, sort_keys=True)

        print("kernel_tag_switch: %d candidate functions with computed jumps written to %s" % (len(candidates), out_dir))
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
