#@category Sandbox
"""
Disassemble across selected memory blocks to ensure instructions exist for follow-on scans.

Args (from scaffold/manual): <out_dir> <build_id> [block_substr] [step] [max_bytes] [exec_only]
  block_substr: case-insensitive substring to match memory block names (default: "sandbox").
    Use "all" to scan all blocks.
  step: byte step between disassembly probes (default: 4).
  max_bytes: limit per block (0 = full block; default: 0).
  exec_only: "1" to scan only executable blocks, "0" to scan all (default: 1).

Outputs: <out_dir>/disasm_report.json
"""

import json
import os
import traceback

_RUN_CALLED = False


def _ensure_out_dir(path):
    if not os.path.isdir(path):
        os.makedirs(path)


def _parse_int(value, default):
    try:
        return int(value, 0)
    except Exception:
        return default


def _block_meta(block):
    return {
        "name": block.getName(),
        "start": "0x%x" % block.getStart().getOffset(),
        "end": "0x%x" % block.getEnd().getOffset(),
        "size": block.getSize(),
        "read": bool(block.isRead()),
        "write": bool(block.isWrite()),
        "execute": bool(block.isExecute()),
    }


def _select_blocks(substr, exec_only):
    mem = currentProgram.getMemory()
    blocks = list(mem.getBlocks())
    if substr == "all":
        picked = blocks
    else:
        needle = substr.lower()
        picked = [blk for blk in blocks if needle in (blk.getName() or "").lower()]
    if exec_only:
        picked = [blk for blk in picked if blk.isExecute()]
    return blocks, picked


def _scan_block(block, step, max_bytes, listing):
    start = block.getStart()
    size = block.getSize()
    scan_size = size
    if max_bytes and max_bytes > 0 and max_bytes < size:
        scan_size = max_bytes
    disasm_calls = 0
    existing_instr = 0
    new_instr = 0
    offset = 0
    while offset < scan_size and not monitor.isCancelled():
        addr = start.add(offset)
        inst = listing.getInstructionAt(addr)
        if inst:
            existing_instr += 1
        else:
            disasm_calls += 1
            try:
                disassemble(addr)
            except Exception:
                pass
            inst = listing.getInstructionAt(addr)
            if inst:
                new_instr += 1
        offset += step
    return {
        "block": _block_meta(block),
        "scan_size": scan_size,
        "step": step,
        "disasm_calls": disasm_calls,
        "existing_instructions": existing_instr,
        "new_instructions": new_instr,
    }


def run():
    global _RUN_CALLED
    if _RUN_CALLED:
        return
    _RUN_CALLED = True
    out_dir = None
    try:
        args = getScriptArgs()
        if len(args) < 1:
            print("usage: kernel_block_disasm.py <out_dir> <build_id> [block_substr] [step] [max_bytes] [exec_only]")
            return
        out_dir = args[0]
        build_id = args[1] if len(args) > 1 else ""
        block_substr = args[2] if len(args) > 2 and args[2] else "sandbox"
        step = _parse_int(args[3], 4) if len(args) > 3 else 4
        max_bytes = _parse_int(args[4], 0) if len(args) > 4 else 0
        exec_only = True
        if len(args) > 5:
            exec_only = str(args[5]).strip() != "0"

        _ensure_out_dir(out_dir)
        all_blocks, picked = _select_blocks(block_substr, exec_only)
        listing = currentProgram.getListing()
        results = []
        for blk in picked:
            results.append(_scan_block(blk, step, max_bytes, listing))

        meta = {
            "build_id": build_id,
            "program": currentProgram.getName(),
            "block_substr": block_substr,
            "step": step,
            "max_bytes": max_bytes,
            "exec_only": exec_only,
            "matched_blocks": len(picked),
            "all_block_names": sorted(set((blk.getName() or "") for blk in all_blocks)),
        }
        with open(os.path.join(out_dir, "disasm_report.json"), "w") as fh:
            json.dump({"meta": meta, "blocks": results}, fh, indent=2, sort_keys=True)
        print("kernel_block_disasm: scanned %d blocks into %s" % (len(picked), out_dir))
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
