#@category Sandbox
"""
Locate likely syscall-dispatch compares against a call code immediate.
Args: <out_dir> <build_id> <imm_hex> [window=<n>] [reg=<w1>] [all]

By default scans sandbox-named blocks; include "all" to scan the entire program.
Outputs: <out_dir>/syscall_code_scan.json
"""

import json
import os
import traceback

from ghidra.program.model.address import AddressSet
from ghidra.program.model.lang import Register

_RUN_CALLED = False
_MNEMONICS = set(["cmp", "cmn", "subs", "adds", "ands", "tst"])


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


def _parse_args(tokens):
    if len(tokens) < 3:
        return None
    out_dir = tokens[0]
    build_id = tokens[1]
    imm = int(tokens[2], 16)
    window = 6
    reg_filter = None
    scan_all = False
    for tok in tokens[3:]:
        low = str(tok).lower()
        if low == "all":
            scan_all = True
        elif low.startswith("window="):
            try:
                window = int(low.split("=", 1)[1], 10)
            except Exception:
                pass
        elif low.startswith("reg="):
            reg_filter = low.split("=", 1)[1]
    return out_dir, build_id, imm, window, reg_filter, scan_all


def _imm_matches(val, imm):
    if val == imm:
        return True
    if imm > (1 << 63):
        if (val & ((1 << 64) - 1)) == imm:
            return True
    return False


def _collect_regs(instr):
    regs = set()
    for op_index in range(instr.getNumOperands()):
        for obj in instr.getOpObjects(op_index):
            if isinstance(obj, Register):
                regs.add(obj.getName().lower())
    return regs


def _collect_imms(instr):
    vals = []
    for op_index in range(instr.getNumOperands()):
        for obj in instr.getOpObjects(op_index):
            try:
                vals.append(int(obj))
            except Exception:
                continue
    return vals


def _context(insts, idx, window):
    start = max(0, idx - window)
    end = min(len(insts), idx + window + 1)
    out = []
    for j in range(start, end):
        inst = insts[j]
        out.append(
            {
                "addr": "0x%x" % inst.getAddress().getOffset(),
                "mnemonic": inst.getMnemonicString(),
                "inst": str(inst),
            }
        )
    return out


def run():
    global _RUN_CALLED
    if _RUN_CALLED:
        return
    _RUN_CALLED = True
    out_dir = None
    try:
        args = getScriptArgs()
        parsed = _parse_args(args)
        if not parsed:
            print("usage: sandbox_syscall_code_scan.py <out_dir> <build_id> <imm_hex> [window=<n>] [reg=<w1>] [all]")
            return
        out_dir, build_id, imm, window, reg_filter, scan_all = parsed
        _ensure_out_dir(out_dir)
        listing = currentProgram.getListing()
        func_mgr = currentProgram.getFunctionManager()
        blocks = list(currentProgram.getMemory().getBlocks()) if scan_all else _sandbox_blocks()
        addr_set = _block_set(blocks)

        insts = []
        inst_iter = listing.getInstructions(addr_set, True)
        while inst_iter.hasNext() and not monitor.isCancelled():
            insts.append(inst_iter.next())

        hits = []
        for idx, instr in enumerate(insts):
            mnemonic = instr.getMnemonicString().lower()
            if mnemonic not in _MNEMONICS:
                continue
            imms = _collect_imms(instr)
            if not any(_imm_matches(val, imm) for val in imms):
                continue
            regs = _collect_regs(instr)
            if reg_filter and reg_filter not in regs:
                continue
            addr = instr.getAddress()
            func = func_mgr.getFunctionContaining(addr)
            hits.append(
                {
                    "address": "0x%x" % addr.getOffset(),
                    "function": func.getName() if func else None,
                    "mnemonic": instr.getMnemonicString(),
                    "inst": str(instr),
                    "registers": sorted(list(regs)),
                    "context": _context(insts, idx, window),
                }
            )

        block_meta = [
            {
                "name": blk.getName(),
                "start": "0x%x" % blk.getStart().getOffset(),
                "end": "0x%x" % blk.getEnd().getOffset(),
            }
            for blk in blocks
        ]
        meta = {
            "build_id": build_id,
            "program": currentProgram.getName(),
            "imm": "0x%x" % imm,
            "window": window,
            "reg_filter": reg_filter,
            "mnemonics": sorted(list(_MNEMONICS)),
            "scan_all_blocks": scan_all,
            "block_filter": block_meta,
            "hit_count": len(hits),
        }
        with open(os.path.join(out_dir, "syscall_code_scan.json"), "w") as f:
            json.dump({"meta": meta, "hits": hits}, f, indent=2, sort_keys=True)
        print("sandbox_syscall_code_scan: %d hits for 0x%x" % (len(hits), imm))
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
