#@category Sandbox
"""
Locate ARM64 ADRP + ADD/SUB immediate pairs that materialize a target address.
Args: <out_dir> <build_id> <target_addr_hex> [lookahead] [all]

Scans sandbox blocks by default; pass "all" to scan the entire program.
Writes JSON to <out_dir>/adrp_add_scan.json with matches and scan metadata.

Pitfalls: assumes ARM64 mnemonics and register semantics; requires a correct processor import. With --no-analysis basic instruction traversal still works.
Notes:
- ADRP computes a page base; ADD/SUB applies a within-page offset.
- Ghidra may represent immediates already shifted; both forms are tried.
"""

import json
import os
import traceback

from ghidra_bootstrap import block_utils, io_utils, scan_utils

from ghidra.program.model.address import AddressSet
from ghidra.program.model.lang import OperandType
from ghidra.program.model.scalar import Scalar
from ghidra.program.model.listing import Instruction

_RUN_CALLED = False


def _ensure_out_dir(path):
    return io_utils.ensure_out_dir(path)

def _sandbox_blocks():
    return block_utils.sandbox_blocks(program=currentProgram)

def _block_set(blocks):
    return block_utils.block_set(blocks)

def _scalar_val(obj):
    if isinstance(obj, Scalar):
        try:
            return obj.getUnsignedValue()
        except Exception:
            try:
                return obj.getValue()
            except Exception:
                return None
    return None


def _is_arm64_adrp(instr):
    return instr.getMnemonicString().upper() == "ADRP"


def _is_add_sub_imm(instr):
    m = instr.getMnemonicString().upper()
    if m not in ("ADD", "SUB"):
        return False
    if instr.getNumOperands() < 3:
        return False
    return (instr.getOperandType(2) & OperandType.SCALAR) != 0


def _same_base_reg(adrp_instr, other_instr):
    try:
        dest = adrp_instr.getOpObjects(0)
        d0 = dest[0] if dest else None
        o0 = other_instr.getOpObjects(0)
        o1 = other_instr.getOpObjects(1)
        return d0 is not None and o0 and o1 and d0 == o0[0] and d0 == o1[0]
    except Exception:
        return False


def _adrp_pages(instr):
    """Return candidate pages computed from ADRP immediate."""
    # Operand 1 usually carries the immediate.
    ops = instr.getOpObjects(1)
    if not ops:
        return []
    imm = _scalar_val(ops[0])
    if imm is None:
        return []
    inst_addr = instr.getAddress().getOffset()
    # Page-align the instruction address to compute ADRP base.
    inst_page = inst_addr & ~0xFFF
    # Depending on processor spec, imm may already be shifted. Try both.
    pages = set()
    pages.add(inst_page + imm)
    pages.add(inst_page + (imm << 12))
    return list(pages)


def _mat_target(page, add_instr):
    ops = add_instr.getOpObjects(2)
    if not ops:
        return None
    imm = _scalar_val(ops[0])
    if imm is None:
        return None
    m = add_instr.getMnemonicString().upper()
    if m == "ADD":
        return page + imm
    return page - imm


def run():
    global _RUN_CALLED
    if _RUN_CALLED:
        return
    _RUN_CALLED = True
    out_dir = None
    try:
        args = getScriptArgs()
        if len(args) < 3:
            print("usage: kernel_adrp_add_scan.py <out_dir> <build_id> <target_addr_hex> [lookahead] [all]")
            return
        out_dir = args[0]
        build_id = args[1]
        target_addr = scan_utils.parse_hex(args[2])
        lookahead = 8
        scan_all = False
        for extra in args[3:]:
            token = str(extra).lower()
            if token == "all":
                scan_all = True
            else:
                try:
                    lookahead = int(extra)
                except Exception:
                    pass
        _ensure_out_dir(out_dir)
        listing = currentProgram.getListing()
        func_mgr = currentProgram.getFunctionManager()
        # By default, focus on sandbox-related blocks to keep scan volume manageable.
        blocks = list(currentProgram.getMemory().getBlocks()) if scan_all else _sandbox_blocks()
        addr_set = _block_set(blocks)
        instr_iter = listing.getInstructions(addr_set, True)
        target_page = target_addr & ~0xFFF
        matches = []
        total_adrp = 0
        while instr_iter.hasNext() and not monitor.isCancelled():
            instr = instr_iter.next()
            if not isinstance(instr, Instruction):
                continue
            if not _is_arm64_adrp(instr):
                continue
            total_adrp += 1
            pages = _adrp_pages(instr)
            if target_page not in pages:
                continue
            # scan forward
            nxt = instr
            for _ in range(lookahead):
                nxt = listing.getInstructionAfter(nxt)
                if nxt is None:
                    break
                if not _is_add_sub_imm(nxt):
                    continue
                if not _same_base_reg(instr, nxt):
                    continue
                candidate = _mat_target(target_page, nxt)
                if candidate == target_addr:
                    func = func_mgr.getFunctionContaining(instr.getAddress())
                    matches.append(
                        {
                            "adrp": scan_utils.format_address(instr.getAddress().getOffset()),
                            "add_sub": scan_utils.format_address(nxt.getAddress().getOffset()),
                            "function": func.getName() if func else None,
                            "add_sub_inst": str(nxt),
                        }
                    )
                    break
        meta = {
            "build_id": build_id,
            "program": currentProgram.getName(),
            "target_addr": scan_utils.format_address(target_addr),
            "target_page": scan_utils.format_address(target_page),
            "lookahead": lookahead,
            "scan_all_blocks": scan_all,
            "adrp_seen": total_adrp,
            "block_filter": [{"name": b.getName(), "start": scan_utils.format_address(b.getStart().getOffset()), "end": scan_utils.format_address(b.getEnd().getOffset())} for b in blocks],
        }
        with open(os.path.join(out_dir, "adrp_add_scan.json"), "w") as f:
            json.dump({"meta": meta, "matches": matches}, f, indent=2, sort_keys=True)
        print("kernel_adrp_add_scan: %d matches (ADRPs seen: %d)" % (len(matches), total_adrp))
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
