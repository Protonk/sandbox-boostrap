#@category Sandbox
"""
Locate ARM64 ADRP + LDR immediate pairs that materialize a target address.
Args: <out_dir> <build_id> <target_addr_hex|auth_got> [lookahead] [all]

Scans sandbox blocks by default; pass "all" to scan the entire program.
Use "auth_got" to record all ADRP+LDR pairs that land inside __auth_got.
Writes JSON to <out_dir>/adrp_ldr_scan.json with matches and scan metadata.
"""

import json
import os
import traceback

from ghidra.program.model.address import AddressSet
from ghidra.program.model.address import Address
from ghidra.program.model.lang import OperandType
from ghidra.program.model.scalar import Scalar
from ghidra.program.model.listing import Instruction

_RUN_CALLED = False
MASK64 = 0xFFFFFFFFFFFFFFFFL


def _u64(val):
    try:
        return long(val) & MASK64
    except Exception:
        return None


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


def _find_got_blocks():
    mem = currentProgram.getMemory()
    blocks = []
    for blk in mem.getBlocks():
        name = (blk.getName() or "").lower()
        if "auth_got" in name:
            blocks.append(blk)
    if blocks:
        return blocks, "auth_got"
    fallback = []
    for blk in mem.getBlocks():
        name = (blk.getName() or "").lower()
        if "got" in name:
            fallback.append(blk)
    return fallback, "got"


def _addr_in_blocks(addr, blocks):
    try:
        a = toAddr(_u64(addr))
    except Exception:
        return None
    for blk in blocks:
        if blk.contains(a):
            return blk
    return None


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


def _is_ldr_imm(instr):
    m = instr.getMnemonicString().upper()
    if not (m.startswith("LDR") or m.startswith("LDRA") or m.startswith("LDUR")):
        return False
    if instr.getNumOperands() < 2:
        return False
    return True


def _same_base_reg(adrp_instr, ldr_instr):
    try:
        dest = adrp_instr.getOpObjects(0)
        d0 = dest[0] if dest else None
        ops = ldr_instr.getOpObjects(1)
        if not d0 or not ops:
            return False
        dname = getattr(d0, "getName", lambda: None)()
        for obj in ops:
            oname = getattr(obj, "getName", lambda: None)()
            if dname and oname and dname == oname:
                return True
    except Exception:
        return False
    return False


def _adrp_pages(instr):
    ops = instr.getOpObjects(1)
    if not ops:
        return []
    if isinstance(ops[0], Address):
        addr = _u64(ops[0].getOffset())
        if addr is None:
            return []
        return [_u64(addr & ~0xFFF)]
    imm = _scalar_val(ops[0])
    if imm is None:
        return []
    inst_addr = _u64(instr.getAddress().getOffset())
    if inst_addr is None:
        return []
    inst_page = _u64(inst_addr & ~0xFFF)
    pages = set()
    pages.add(_u64(inst_page + imm))
    pages.add(_u64(inst_page + (imm << 12)))
    return [p for p in pages if p is not None]


def _ldr_offset(instr):
    ops = instr.getOpObjects(1)
    if not ops:
        return None
    for obj in ops:
        val = _scalar_val(obj)
        if val is not None:
            return val
    return 0


def run():
    global _RUN_CALLED
    if _RUN_CALLED:
        return
    _RUN_CALLED = True
    out_dir = None
    try:
        args = getScriptArgs()
        if len(args) < 3:
            print("usage: kernel_adrp_ldr_scan.py <out_dir> <build_id> <target_addr_hex> [lookahead] [all]")
            return
        out_dir = args[0]
        build_id = args[1]
        target_token = str(args[2]).lower()
        target_addr = None
        target_page = None
        target_mode = "target"
        got_blocks = []
        got_mode = None
        if target_token in ("auth_got", "got", "auth-got"):
            target_mode = "auth_got"
            got_blocks, got_mode = _find_got_blocks()
        else:
            target_addr = _u64(int(args[2], 16))
            target_page = _u64(target_addr & ~0xFFF) if target_addr is not None else None
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
        blocks = list(currentProgram.getMemory().getBlocks()) if scan_all else _sandbox_blocks()
        addr_set = _block_set(blocks)
        instr_iter = listing.getInstructions(addr_set, True)
        matches = []
        seen = set()
        total_adrp = 0
        while instr_iter.hasNext() and not monitor.isCancelled():
            instr = instr_iter.next()
            if not isinstance(instr, Instruction):
                continue
            if not _is_arm64_adrp(instr):
                continue
            total_adrp += 1
            pages = _adrp_pages(instr)
            if target_mode == "target" and target_page not in pages:
                continue
            nxt = instr
            for _ in range(lookahead):
                nxt = listing.getInstructionAfter(nxt.getAddress()) if nxt else None
                if nxt is None:
                    break
                if not _is_ldr_imm(nxt):
                    continue
                if not _same_base_reg(instr, nxt):
                    continue
                offset = _ldr_offset(nxt) or 0
                matched = False
                for page in pages:
                    candidate = _u64(page + offset)
                    if candidate is None:
                        continue
                    if target_mode == "auth_got":
                        blk = _addr_in_blocks(candidate, got_blocks)
                        if not blk:
                            continue
                        func = func_mgr.getFunctionContaining(instr.getAddress())
                        loaded = None
                        try:
                            loaded = currentProgram.getMemory().getLong(toAddr(candidate))
                        except Exception:
                            loaded = None
                        key = (instr.getAddress().getOffset(), nxt.getAddress().getOffset(), candidate)
                        if key in seen:
                            matched = True
                            break
                        seen.add(key)
                        entry = {
                            "adrp": "0x%x" % instr.getAddress().getOffset(),
                            "ldr": "0x%x" % nxt.getAddress().getOffset(),
                            "function": func.getName() if func else None,
                            "ldr_inst": str(nxt),
                            "effective_addr": "0x%x" % candidate,
                            "got_block": blk.getName(),
                        }
                        if loaded is not None:
                            entry["loaded_value"] = "0x%x" % loaded
                        matches.append(entry)
                        matched = True
                        break
                    if candidate == target_addr:
                        func = func_mgr.getFunctionContaining(instr.getAddress())
                        key = (instr.getAddress().getOffset(), nxt.getAddress().getOffset(), candidate)
                        if key in seen:
                            matched = True
                            break
                        seen.add(key)
                        matches.append(
                            {
                                "adrp": "0x%x" % instr.getAddress().getOffset(),
                                "ldr": "0x%x" % nxt.getAddress().getOffset(),
                                "function": func.getName() if func else None,
                                "ldr_inst": str(nxt),
                            }
                        )
                        matched = True
                        break
                if matched:
                    break
        meta = {
            "build_id": build_id,
            "program": currentProgram.getName(),
            "target_mode": target_mode,
            "target_addr": "0x%x" % target_addr if target_addr is not None else None,
            "target_page": "0x%x" % target_page if target_page is not None else None,
            "lookahead": lookahead,
            "scan_all_blocks": scan_all,
            "adrp_seen": total_adrp,
            "got_block_mode": got_mode if got_blocks else None,
            "got_blocks": [
                {
                    "name": b.getName(),
                    "start": "0x%x" % b.getStart().getOffset(),
                    "end": "0x%x" % b.getEnd().getOffset(),
                }
                for b in got_blocks
            ],
            "block_filter": [
                {"name": b.getName(), "start": "0x%x" % b.getStart().getOffset(), "end": "0x%x" % b.getEnd().getOffset()}
                for b in blocks
            ],
        }
        with open(os.path.join(out_dir, "adrp_ldr_scan.json"), "w") as f:
            json.dump({"meta": meta, "matches": matches}, f, indent=2, sort_keys=True)
        print("kernel_adrp_ldr_scan: %d matches (ADRPs seen: %d)" % (len(matches), total_adrp))
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
