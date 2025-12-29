#@category Sandbox
"""
Scan sandbox-related code for mask immediates used on the third node payload (field2/filter_arg).
Args: <out_dir> <build_id> [mask_hex ...] [all]
Defaults to masks 0x3fff, 0x4000, 0xc000 if none provided. Add "all" to scan the entire binary
instead of sandbox memory blocks only.

Outputs: dumps/ghidra/out/<build>/kernel-field2-mask-scan/mask_scan.json (plus script.log).
Pitfalls: with --no-analysis basic instruction iteration still works, but function metadata/xrefs will be sparse.
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


def _parse_masks(args):
    masks = []
    scan_all = False
    for a in args:
        if a.lower() == "all":
            scan_all = True
            continue
        try:
            masks.append(int(a, 16))
        except Exception:
            continue
    if not masks:
        masks = [0x3FFF, 0x4000, 0xC000]
    return masks, scan_all


def run():
    global _RUN_CALLED
    if _RUN_CALLED:
        return
    _RUN_CALLED = True
    out_dir = None
    try:
        args = getScriptArgs()
        if len(args) < 2:
            print("usage: kernel_field2_mask_scan.py <out_dir> <build_id> [mask_hex ...] [all]")
            return
        out_dir = args[0]
        build_id = args[1]
        masks, scan_all = _parse_masks(args[2:])
        _ensure_out_dir(out_dir)
        listing = currentProgram.getListing()
        func_mgr = currentProgram.getFunctionManager()
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

        hits = {m: [] for m in masks}
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
                    for m in masks:
                        if val == m or (m > (1 << 63) and (val & ((1 << 64) - 1)) == m):
                            addr = instr.getAddress()
                            func = func_mgr.getFunctionContaining(addr)
                            hits[m].append(
                                {
                                    "address": scan_utils.format_address(addr.getOffset()),
                                    "function": func.getName() if func else None,
                                    "mnemonic": instr.getMnemonicString(),
                                    "inst": str(instr),
                                }
                            )
                            break

        meta = {
            "build_id": build_id,
            "program": currentProgram.getName(),
            "masks": [scan_utils.format_address(m) for m in masks],
            "scan_all_blocks": scan_all,
            "block_filter": block_meta,
        }
        out = {"meta": meta, "hits": {hex(m): hits[m] for m in masks}}
        with open(os.path.join(out_dir, "mask_scan.json"), "w") as f:
            json.dump(out, f, indent=2, sort_keys=True)
        print("kernel_field2_mask_scan: wrote hits for %d masks to %s" % (len(masks), out_dir))
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
