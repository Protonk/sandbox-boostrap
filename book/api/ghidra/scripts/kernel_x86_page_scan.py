#@category Sandbox
"""
Scan x86/x86_64 instructions for immediates or RIP-relative displacements that
resolve to a target address/page.
Args: <out_dir> <build_id> <target_addr_hex> [page_size_hex] [all]

For each instruction operand:
  - If it is an Address, check if it falls in the target page.
  - If it is a Scalar:
      * If operand type is RELATIVE, compute (next_instr + imm) and test page.
      * Otherwise treat imm as absolute and test page.

By default scans sandbox blocks; pass "all" to scan entire program.
Outputs JSON to <out_dir>/x86_page_scan.json.

IMPORTANT: This is an x86-specific helper. On Apple Silicon / ARM64 kernels
it will not find ADRP/ADD/LDR-style materializations and should not be treated
as evidence for or against usage of an address. Use ARM64-aware scans instead
when working with macOS 13–14 targets.

Notes:
- Page size defaults to 4K, matching typical kernel page alignment.
- RELATIVE operands are interpreted as RIP-relative displacements.
"""

import json
import os
import traceback

from ghidra_bootstrap import block_utils, io_utils, scan_utils

from ghidra.program.model.address import AddressSet
from ghidra.program.model.lang import OperandType
from ghidra.program.model.listing import Instruction
from ghidra.program.model.scalar import Scalar
from ghidra.program.model.address import Address

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
            return obj.getSignedValue()
        except Exception:
            try:
                return obj.getValue()
            except Exception:
                return None
    return None


def _in_page(val, start, end):
    return start <= val <= end


def _u64(val):
    return val & ((1 << 64) - 1)


def run():
    global _RUN_CALLED
    if _RUN_CALLED:
        return
    _RUN_CALLED = True
    out_dir = None
    try:
        args = getScriptArgs()
        if len(args) < 3:
            print("usage: kernel_x86_page_scan.py <out_dir> <build_id> <target_addr_hex> [page_size_hex] [all]")
            return
        out_dir = args[0]
        build_id = args[1]
        target_addr = scan_utils.parse_hex(args[2])
        # Default to 4K pages for address range matching.
        page_size = 0x1000
        scan_all = False
        for extra in args[3:]:
            token = str(extra).lower()
            if token == "all":
                scan_all = True
            else:
                try:
                    page_size = int(extra, 16)
                except Exception:
                    pass
        target_u = _u64(target_addr)
        page_start = target_u & ~(page_size - 1)
        page_end = page_start + page_size - 1
        _ensure_out_dir(out_dir)
        listing = currentProgram.getListing()
        blocks = list(currentProgram.getMemory().getBlocks()) if scan_all else _sandbox_blocks()
        addr_set = _block_set(blocks)
        instr_iter = listing.getInstructions(addr_set, True)
        matches = []
        total_instr = 0
        while instr_iter.hasNext() and not monitor.isCancelled():
            instr = instr_iter.next()
            if not isinstance(instr, Instruction):
                continue
            total_instr += 1
            addr = instr.getAddress()
            inst_len = instr.getLength()
            next_addr_val = _u64(addr.add(inst_len).getOffset())
            for op_index in range(instr.getNumOperands()):
                op_type = instr.getOperandType(op_index)
                objs = instr.getOpObjects(op_index)
                for obj in objs:
                    # Direct address operand
                    if isinstance(obj, Address):
                        val = _u64(obj.getOffset())
                        if _in_page(val, page_start, page_end):
                            matches.append(
                                {
                                    "address": scan_utils.format_address(_u64(addr.getOffset())),
                                    "mnemonic": instr.getMnemonicString(),
                                    "inst": str(instr),
                                    "operand_index": op_index,
                                    "mode": "address",
                                    "target": scan_utils.format_address(val),
                                }
                            )
                            break
                    # Scalar operand
                    sval = _scalar_val(obj)
                    if sval is None:
                        continue
                    # Normalize to unsigned 64-bit for comparison
                    sval64 = _u64(sval)
                    if op_type & OperandType.RELATIVE:
                        # RIP-relative addressing: target is next instruction + displacement.
                        tgt = _u64(next_addr_val + sval)
                        if _in_page(tgt, page_start, page_end):
                            matches.append(
                                {
                                    "address": scan_utils.format_address(_u64(addr.getOffset())),
                                    "mnemonic": instr.getMnemonicString(),
                                    "inst": str(instr),
                                    "operand_index": op_index,
                                    "mode": "relative",
                                    "target": scan_utils.format_address(tgt),
                                }
                            )
                            break
                    else:
                        if _in_page(sval64, page_start, page_end):
                            matches.append(
                                {
                                    "address": scan_utils.format_address(_u64(addr.getOffset())),
                                    "mnemonic": instr.getMnemonicString(),
                                    "inst": str(instr),
                                    "operand_index": op_index,
                                    "mode": "absolute",
                                    "target": scan_utils.format_address(sval64),
                                }
                            )
                            break
        meta = {
            "build_id": build_id,
            "program": currentProgram.getName(),
            "target_addr": scan_utils.format_address(target_u),
            "page_start": scan_utils.format_address(page_start),
            "page_end": scan_utils.format_address(page_end),
            "page_size": scan_utils.format_address(page_size),
            "scan_all_blocks": scan_all,
            "block_filter": [{"name": b.getName(), "start": scan_utils.format_address(b.getStart().getOffset()), "end": scan_utils.format_address(b.getEnd().getOffset())} for b in blocks],
            "instructions_scanned": total_instr,
        }
        with open(os.path.join(out_dir, "x86_page_scan.json"), "w") as f:
            json.dump({"meta": meta, "matches": matches}, f, indent=2, sort_keys=True)
        print("kernel_x86_page_scan: %d matches (instructions scanned: %d)" % (len(matches), total_instr))
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
