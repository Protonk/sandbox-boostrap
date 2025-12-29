#@category Sandbox
"""
Scan ARM64 instructions for ADRP/ADD/LDR sequences that materialize addresses
within a target segment/page range (e.g., __const/__desc) even if the exact
pointer literal is absent.
Args: <out_dir> <build_id> <start_addr_hex> <end_addr_hex> [lookahead] [all]

Heuristic:
- For each ADRP that lands within [start,end], scan forward N instructions
  for ADD/SUB (imm) using the same base register and record the computed target.
- Also record LDR/LDUR (register) that use the same base register as ADRP;
  this flags base+offset loads into the segment.

Outputs JSON to <out_dir>/arm_const_base_scan.json.

Pitfalls: assumes ARM64 instruction set; ensure processor import is ARM64. With --no-analysis, function info may be missing but linear instruction scanning still works.
Notes:
- Range inputs are treated as signed addresses to align with Ghidra's internal offsets.
- ADRP immediates can be pre-shifted by the processor spec; both forms are checked.
"""

import json
import os
import traceback

from ghidra_bootstrap import block_utils, io_utils, scan_utils

from ghidra.program.model.address import AddressSet
from ghidra.program.model.lang import OperandType
from ghidra.program.model.listing import Instruction
from ghidra.program.model.scalar import Scalar
from ghidra.program.model.lang import Register

_RUN_CALLED = False


def _ensure_out_dir(path):
    return io_utils.ensure_out_dir(path)

def _s64(val):
    return scan_utils.to_signed(val)


def _format_addr(value):
    return scan_utils.format_signed_hex(value)


def _parse_hex_address(text):
    return scan_utils.parse_signed_hex(text)


def _sandbox_blocks():
    return block_utils.sandbox_blocks(program=currentProgram)

def _block_set(blocks):
    return block_utils.block_set(blocks)

def _scalar(obj):
    if isinstance(obj, Scalar):
        try:
            return obj.getSignedValue()
        except Exception:
            try:
                return obj.getValue()
            except Exception:
                return None
    return None


def _is_arm64_adrp(instr):
    return instr.getMnemonicString().upper() == "ADRP"


def _adrp_page(instr):
    ops = instr.getOpObjects(1)
    if not ops:
        return []
    imm = _scalar(ops[0])
    if imm is None:
        return []
    inst_addr = _s64(instr.getAddress().getOffset())
    inst_page = _s64(inst_addr & ~0xFFF)
    # Try both interpretations (imm already shifted vs page offset)
    return [_s64(inst_page + imm), _s64(inst_page + (imm << 12))]


def _same_base_reg(adrp_instr, other_instr):
    try:
        d0 = adrp_instr.getOpObjects(0)
        dest = d0[0] if d0 else None
        if dest is None:
            return False
        o1 = other_instr.getOpObjects(0)
        o2 = other_instr.getOpObjects(1)
        objs = list(o1) + list(o2)
        return any(isinstance(x, Register) and x == dest for x in objs)
    except Exception:
        return False


def _is_add_sub_imm(instr):
    m = instr.getMnemonicString().upper()
    if m not in ("ADD", "SUB"):
        return False
    return (instr.getOperandType(2) & OperandType.SCALAR) != 0


def _is_ldr_like(instr):
    m = instr.getMnemonicString().upper()
    return m.startswith("LDR") or m.startswith("LDUR")


def run():
    global _RUN_CALLED
    if _RUN_CALLED:
        return
    _RUN_CALLED = True
    out_dir = None
    try:
        args = getScriptArgs()
        if len(args) < 4:
            print("usage: kernel_arm_const_base_scan.py <out_dir> <build_id> <start_addr_hex> <end_addr_hex> [lookahead] [all]")
            return
        out_dir = args[0]
        build_id = args[1]
        start_addr = _parse_hex_address(args[2])
        end_addr = _parse_hex_address(args[3])
        if start_addr is None or end_addr is None:
            print("invalid range args: %s %s" % (args[2], args[3]))
            return
        if start_addr > end_addr:
            # Accept reversed ranges to make ad hoc use less error-prone.
            start_addr, end_addr = end_addr, start_addr
        lookahead = 8
        scan_all = False
        for extra in args[4:]:
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
        # Default to sandbox blocks so the scan stays focused and fast.
        blocks = list(currentProgram.getMemory().getBlocks()) if scan_all else _sandbox_blocks()
        addr_set = _block_set(blocks)
        instr_iter = listing.getInstructions(addr_set, True)
        matches = {"adrp_add": [], "adrp_ldr": []}
        total_adrp = 0
        while instr_iter.hasNext() and not monitor.isCancelled():
            instr = instr_iter.next()
            if not isinstance(instr, Instruction):
                continue
            if not _is_arm64_adrp(instr):
                continue
            pages = _adrp_page(instr)
            hit_page = [p for p in pages if start_addr <= p <= end_addr]
            if not hit_page:
                continue
            total_adrp += 1
            base_page = hit_page[0]
            # scan forward
            nxt = instr
            for _ in range(lookahead):
                nxt = listing.getInstructionAfter(nxt)
                if nxt is None:
                    break
                if _is_add_sub_imm(nxt) and _same_base_reg(instr, nxt):
                    imm = _scalar(nxt.getOpObjects(2)[0])
                    if imm is None:
                        continue
                    target = _s64(base_page + imm) if nxt.getMnemonicString().upper() == "ADD" else _s64(base_page - imm)
                    if start_addr <= target <= end_addr:
                        func = func_mgr.getFunctionContaining(instr.getAddress())
                        matches["adrp_add"].append(
                            {
                                "adrp": _format_addr(_s64(instr.getAddress().getOffset())),
                                "add_sub": _format_addr(_s64(nxt.getAddress().getOffset())),
                                "target": _format_addr(target),
                                "function": func.getName() if func else None,
                                "add_sub_inst": str(nxt),
                            }
                        )
                        break
                if _is_ldr_like(nxt) and _same_base_reg(instr, nxt):
                    # Record base+offset access into the segment.
                    func = func_mgr.getFunctionContaining(instr.getAddress())
                    matches["adrp_ldr"].append(
                        {
                            "adrp": _format_addr(_s64(instr.getAddress().getOffset())),
                            "ldr": _format_addr(_s64(nxt.getAddress().getOffset())),
                            "ldr_inst": str(nxt),
                            "function": func.getName() if func else None,
                        }
                    )
        meta = {
            "build_id": build_id,
            "program": currentProgram.getName(),
            "range_start": _format_addr(start_addr),
            "range_end": _format_addr(end_addr),
            "lookahead": lookahead,
            "scan_all_blocks": scan_all,
            "adrp_seen": total_adrp,
            "block_filter": [
                {
                    "name": b.getName(),
                    "start": _format_addr(_s64(b.getStart().getOffset())),
                    "end": _format_addr(_s64(b.getEnd().getOffset())),
                }
                for b in blocks
            ],
        }
        with open(os.path.join(out_dir, "arm_const_base_scan.json"), "w") as f:
            json.dump({"meta": meta, "matches": matches}, f, indent=2, sort_keys=True)
        print("kernel_arm_const_base_scan: ADRP seen %d, matches add:%d ldr:%d" % (total_adrp, len(matches["adrp_add"]), len(matches["adrp_ldr"])))
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
