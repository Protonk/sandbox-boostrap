#@category Sandbox
"""
Locate references into a target page (useful for ADRP/ADD pointer materialization).
Args: <out_dir> <build_id> <target_addr_hex> [page_size_hex] [all]

Finds instructions that reference any address within the target page via Ghidra
references and also detects ADRP + ADD immediate pairs that land inside the page.
By default, only sandbox memory blocks are scanned; pass "all" to scan the entire
program. Results are written to JSON in <out_dir>/page_refs.json.

Pitfalls: processor must be ARM64 for ADRP/ADD recognition; --no-analysis reduces xref quality but immediate scans still run.
Notes:
- Page size defaults to 4K, matching kernel page alignment.
- ADRP+ADD detection is heuristic and bounded to a short lookahead window.
"""

import json
import os
import traceback

from ghidra_bootstrap import block_utils, io_utils, scan_utils

from ghidra.program.model.address import AddressSet
from ghidra.program.model.scalar import Scalar
from ghidra.program.model.lang import Register

_RUN_CALLED = False


def _ensure_out_dir(path):
    return io_utils.ensure_out_dir(path)

def _sandbox_blocks():
    return block_utils.sandbox_blocks(program=currentProgram)

def _block_set(blocks):
    return block_utils.block_set(blocks)

def _scalar_value(obj):
    if isinstance(obj, Scalar):
        try:
            return obj.getUnsignedValue()
        except Exception:
            try:
                return obj.getValue()
            except Exception:
                return None
    return None


def _reg_equal(a, b):
    return isinstance(a, Register) and isinstance(b, Register) and a == b


def _detect_adrp_pairs(instr_iter_start, dest_reg, base_page, page_start, page_end):
    """Look forward a few instructions for ADD dest_reg, dest_reg, #imm landing in range."""
    hits = []
    nxt = instr_iter_start
    steps = 0
    while nxt is not None and steps < 6 and not monitor.isCancelled():
        nxt = nxt.getNext()
        steps += 1
        if nxt is None:
            break
        if nxt.getInstructionPrototype() is None:
            continue
        # Collect registers in operands.
        regs = []
        for op_index in range(nxt.getNumOperands()):
            for obj in nxt.getOpObjects(op_index):
                if isinstance(obj, Register):
                    regs.append(obj)
        writes_dest = any(_reg_equal(obj, dest_reg) for obj in nxt.getOpObjects(0))
        uses_dest = any(_reg_equal(r, dest_reg) for r in regs)
        if not uses_dest:
            # If destination is clobbered, stop scanning.
            if writes_dest:
                break
            continue
        mnemonic = nxt.getMnemonicString().upper()
        if mnemonic in ("ADD", "ADDS"):
            imm = None
            for op_index in range(nxt.getNumOperands()):
                for obj in nxt.getOpObjects(op_index):
                    imm_val = _scalar_value(obj)
                    if imm_val is not None:
                        imm = imm_val
                        break
                if imm is not None:
                    break
            if imm is None:
                continue
            target = base_page + imm
            if page_start <= target <= page_end:
                hits.append(
                    {
                        "adrp": scan_utils.format_address(instr_iter_start.getAddress().getOffset()),
                        "add": scan_utils.format_address(nxt.getAddress().getOffset()),
                        "target": scan_utils.format_address(target),
                        "add_inst": str(nxt),
                    }
                )
                break
        # If the destination register is overwritten, bail out after processing.
        if writes_dest and mnemonic not in ("NOP",):
            break
    return hits


def run():
    global _RUN_CALLED
    if _RUN_CALLED:
        return
    _RUN_CALLED = True
    out_dir = None
    try:
        args = getScriptArgs()
        if len(args) < 3:
            print("usage: kernel_page_ref_scan.py <out_dir> <build_id> <target_addr_hex> [page_size_hex] [all]")
            return
        out_dir = args[0]
        build_id = args[1]
        target_addr = scan_utils.parse_hex(args[2])
        # Default to 4K pages; override when scanning large segments.
        page_size = 0x1000
        scan_all = False
        if len(args) > 3:
            for extra in args[3:]:
                token = str(extra).lower()
                if token == "all":
                    scan_all = True
                else:
                    try:
                        page_size = int(extra, 16)
                    except Exception:
                        pass
        # Page-align the target to compute bounds for reference matching.
        page_start = target_addr & ~0xFFF
        page_end = page_start + page_size - 1
        _ensure_out_dir(out_dir)
        listing = currentProgram.getListing()
        func_mgr = currentProgram.getFunctionManager()
        ref_mgr = currentProgram.getReferenceManager()
        blocks = list(currentProgram.getMemory().getBlocks()) if scan_all else _sandbox_blocks()
        addr_set = _block_set(blocks)
        ref_hits = []
        adrp_hits = []
        instr_iter = listing.getInstructions(addr_set, True)
        while instr_iter.hasNext() and not monitor.isCancelled():
            instr = instr_iter.next()
            addr = instr.getAddress()
            func = func_mgr.getFunctionContaining(addr)
            # Direct references into the page.
            for ref in ref_mgr.getReferencesFrom(addr):
                to_addr = ref.getToAddress()
                to_val = to_addr.getOffset()
                if page_start <= to_val <= page_end:
                    ref_hits.append(
                        {
                            "from": scan_utils.format_address(addr.getOffset()),
                            "to": scan_utils.format_address(to_val),
                            "mnemonic": instr.getMnemonicString(),
                            "inst": str(instr),
                            "function": func.getName() if func else None,
                        }
                    )
            # ADRP + ADD pair landing in the page.
            if instr.getMnemonicString().upper() == "ADRP":
                # Try to extract destination register and referenced page.
                dest_reg = None
                if instr.getNumOperands() > 0:
                    objs = instr.getOpObjects(0)
                    if objs and isinstance(objs[0], Register):
                        dest_reg = objs[0]
                refs = list(ref_mgr.getReferencesFrom(addr))
                target_page = None
                for ref in refs:
                    to_addr = ref.getToAddress()
                    target_page = to_addr.getOffset() & ~0xFFF
                    break
                if dest_reg and target_page is not None and page_start <= target_page <= page_end:
                    adrp_hits.extend(_detect_adrp_pairs(instr, dest_reg, target_page, page_start, page_end))
        meta = {
            "build_id": build_id,
            "program": currentProgram.getName(),
            "target_addr": scan_utils.format_address(target_addr),
            "page_start": scan_utils.format_address(page_start),
            "page_end": scan_utils.format_address(page_end),
            "page_size": scan_utils.format_address(page_size),
            "scan_all_blocks": scan_all,
            "block_filter": [{"name": b.getName(), "start": scan_utils.format_address(b.getStart().getOffset()), "end": scan_utils.format_address(b.getEnd().getOffset())} for b in blocks],
        }
        with open(os.path.join(out_dir, "page_refs.json"), "w") as f:
            json.dump({"meta": meta, "ref_hits": ref_hits, "adrp_add_hits": adrp_hits}, f, indent=2, sort_keys=True)
        print("kernel_page_ref_scan: %d direct refs, %d adrp/add hits" % (len(ref_hits), len(adrp_hits)))
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
