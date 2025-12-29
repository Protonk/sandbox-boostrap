#@category Sandbox
"""
Map stub-like sequences to GOT entries (auth_got/auth_ptr/got) for arm64e binaries.

Args: <out_dir> <build_id> [block_substr] [lookahead] [exec_only] [all]
  block_substr: case-insensitive substring to match blocks (default: "stub").
    Use "all" to scan every block.
  lookahead: number of instructions to scan after ADRP / backward for BLR (default: 6).
  exec_only: "1" to scan only executable blocks (default), "0" to include all.
  all: optional flag to ignore block_substr and scan all blocks.

Outputs: <out_dir>/stub_got_map.json

Notes:
- __auth_got/__auth_ptr contain pointer-authenticated entries; keep them distinct.
- Stubs are matched by ADRP/ADD/LDR/BLR patterns and are inherently heuristic.
"""

import json
import os
import traceback

from ghidra_bootstrap import block_utils, io_utils, scan_utils

from ghidra.program.model.address import Address, AddressSet
from ghidra.program.model.lang import Register
from ghidra.program.model.mem import MemoryAccessException
from ghidra.program.model.listing import Instruction
from ghidra.program.model.scalar import Scalar

_RUN_CALLED = False


def _u64(val):
    return scan_utils.to_unsigned(val)


def _s64(val):
    return scan_utils.to_signed(val)


def _format_addr(value):
    return scan_utils.format_signed_hex(value)


def _ensure_out_dir(path):
    return io_utils.ensure_out_dir(path)

def _parse_int(value, default):
    try:
        return int(value, 0)
    except Exception:
        return default


def _find_got_blocks():
    mem = currentProgram.getMemory()
    blocks = []
    kinds = []
    for blk in mem.getBlocks():
        name = (blk.getName() or "").lower()
        kind = None
        if "auth_got" in name:
            kind = "auth_got"
        elif "auth_ptr" in name:
            kind = "auth_ptr"
        elif "got" in name:
            kind = "got"
        if not kind:
            continue
        blocks.append(blk)
        kinds.append(kind)
    # Collapse block kinds into a single mode label for metadata.
    mode = "+".join(sorted(set(kinds))) if kinds else None
    return blocks, mode


def _select_blocks(substr, exec_only, scan_all):
    mem = currentProgram.getMemory()
    blocks = list(mem.getBlocks())
    if scan_all or substr == "all":
        picked = blocks
    else:
        needle = substr.lower()
        # Block names vary by KC slice; substring matching is more robust than exact names.
        picked = [blk for blk in blocks if needle in (blk.getName() or "").lower()]
    if exec_only:
        picked = [blk for blk in picked if blk.isExecute()]
    return blocks, picked


def _block_set(blocks):
    return block_utils.block_set(blocks)

def _addr_in_blocks(addr, blocks):
    try:
        a = toAddr(_s64(addr))
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


def _normalize_reg(name):
    if not name:
        return None
    name = name.lower()
    # Normalize register width to xN to simplify matching across operand forms.
    if name.startswith("w") and name[1:].isdigit():
        return "x" + name[1:]
    return name


def _reg_name(obj):
    try:
        return obj.getName()
    except Exception:
        return None


def _adrp_dest_reg(instr):
    ops = instr.getOpObjects(0)
    if not ops:
        return None
    return _normalize_reg(_reg_name(ops[0]))


def _adrp_pages(instr):
    ops = instr.getOpObjects(1)
    if not ops:
        return []
    if isinstance(ops[0], Address):
        addr = _s64(ops[0].getOffset())
        if addr is None:
            return []
        return [_s64(addr & ~0xFFF)]
    imm = _scalar_val(ops[0])
    if imm is None:
        return []
    inst_addr = _s64(instr.getAddress().getOffset())
    if inst_addr is None:
        return []
    inst_page = _s64(inst_addr & ~0xFFF)
    pages = set()
    pages.add(_s64(inst_page + imm))
    pages.add(_s64(inst_page + (imm << 12)))
    return [p for p in pages if p is not None]


def _add_sub_imm(instr):
    m = instr.getMnemonicString().upper()
    if m not in ("ADD", "SUB"):
        return None
    if instr.getNumOperands() < 3:
        return None
    dest = None
    src = None
    imm = None
    for obj in instr.getOpObjects(0):
        if isinstance(obj, Register):
            dest = _normalize_reg(obj.getName())
            break
    for obj in instr.getOpObjects(1):
        if isinstance(obj, Register):
            src = _normalize_reg(obj.getName())
            break
    for obj in instr.getOpObjects(2):
        val = _scalar_val(obj)
        if val is not None:
            imm = val
            break
    if dest and src and imm is not None:
        sign = 1 if m == "ADD" else -1
        return dest, src, imm, sign
    return None


def _ldr_base_offset(instr):
    if instr.getNumOperands() < 2:
        return None, None
    base = None
    offset = 0
    for obj in instr.getOpObjects(1):
        if isinstance(obj, Register):
            base = _normalize_reg(obj.getName())
        else:
            val = _scalar_val(obj)
            if val is not None:
                offset = val
    return base, offset


def _ldr_literal_addr(instr):
    for i in range(instr.getNumOperands()):
        for obj in instr.getOpObjects(i):
            if isinstance(obj, Address):
                return _s64(obj.getOffset())
    return None


def _is_arm64_adrp(instr):
    return instr.getMnemonicString().upper() == "ADRP"


def _is_ldr(instr):
    m = instr.getMnemonicString().upper()
    if not (m.startswith("LDR") or m.startswith("LDRA") or m.startswith("LDUR")):
        return False
    return instr.getNumOperands() >= 2


def _is_branch(instr):
    m = instr.getMnemonicString().upper()
    if m.startswith("BR") or m.startswith("BLR"):
        return True
    return False


def _first_address_operand(instr):
    for i in range(instr.getNumOperands()):
        for obj in instr.getOpObjects(i):
            if isinstance(obj, Address):
                return _s64(obj.getOffset())
    return None


def _first_scalar_operand(instr):
    for i in range(instr.getNumOperands()):
        for obj in instr.getOpObjects(i):
            if isinstance(obj, Scalar):
                return _scalar_val(obj)
    return None


def _first_register_operand(instr, op_index=None):
    if op_index is not None and op_index < instr.getNumOperands():
        for obj in instr.getOpObjects(op_index):
            if isinstance(obj, Register):
                return _normalize_reg(obj.getName())
        return None
    for i in range(instr.getNumOperands()):
        for obj in instr.getOpObjects(i):
            if isinstance(obj, Register):
                return _normalize_reg(obj.getName())
    return None


def _writes_reg(instr, reg_name):
    try:
        results = instr.getResultObjects()
    except Exception:
        results = []
    for obj in results or []:
        if isinstance(obj, Register):
            if _normalize_reg(obj.getName()) == reg_name:
                return True
    return False


def _call_target_register(instr):
    return _first_register_operand(instr, 0)


def _read_ptr(memory, addr):
    if addr is None or addr == 0:
        return None
    try:
        return _u64(memory.getLong(toAddr(_s64(addr))))
    except (MemoryAccessException, Exception):
        return None


def _result_value(value, source, instr=None, mem_addr=None, loaded=None):
    out = {"value": _format_addr(value), "source": source, "_value_int": value}
    if instr is not None:
        out["instruction"] = instr.toString()
    if mem_addr is not None:
        out["mem_addr"] = _format_addr(mem_addr)
    if loaded is not None:
        out["loaded_value"] = _format_addr(loaded)
    return out


def _resolve_reg_value(start_instr, reg_name, memory, max_back=16, depth=2):
    instr = start_instr
    steps = 0
    pending = None
    while instr and steps < max_back and not monitor.isCancelled():
        if not _writes_reg(instr, reg_name):
            instr = instr.getPrevious()
            steps += 1
            continue
        mnemonic = instr.getMnemonicString().upper()
        if mnemonic in ("ADRP", "ADR"):
            base = _first_address_operand(instr)
            if base is None:
                return {"value": None, "source": "adrp_no_addr", "instruction": instr.toString()}
            if pending:
                value = _s64(base + pending["delta"])
                if pending["kind"] == "ldr":
                    loaded = _read_ptr(memory, value)
                    return _result_value(value, "%s+ldr" % mnemonic.lower(), instr, mem_addr=value, loaded=loaded)
                return _result_value(value, "%s+%s" % (mnemonic.lower(), pending["kind"]), instr)
            return _result_value(base, mnemonic.lower(), instr)
        if mnemonic in ("ADD", "SUB"):
            src_reg = _first_register_operand(instr, 1)
            scalar = _first_scalar_operand(instr)
            if scalar is not None and src_reg:
                sign = 1 if mnemonic == "ADD" else -1
                if src_reg == reg_name:
                    pending = {"kind": "add", "delta": sign * scalar}
                    instr = instr.getPrevious()
                    steps += 1
                    continue
                if depth > 0:
                    base_val = _resolve_reg_value(instr.getPrevious(), src_reg, memory, max_back, depth - 1)
                    base_int = base_val.get("_value_int") if base_val else None
                    if base_int is not None:
                        value = _s64(base_int + sign * scalar)
                        return _result_value(value, "%s+%s" % (base_val.get("source"), mnemonic.lower()), instr)
        if mnemonic.startswith("LDR") or mnemonic.startswith("LDRA") or mnemonic.startswith("LDUR"):
            base_reg, offset = _ldr_base_offset(instr)
            offset = offset or 0
            if base_reg:
                if base_reg == reg_name:
                    pending = {"kind": "ldr", "delta": offset}
                    instr = instr.getPrevious()
                    steps += 1
                    continue
                if depth > 0:
                    base_val = _resolve_reg_value(instr.getPrevious(), base_reg, memory, max_back, depth - 1)
                    base_int = base_val.get("_value_int") if base_val else None
                    if base_int is not None:
                        mem_addr = _s64(base_int + offset)
                        loaded = _read_ptr(memory, mem_addr)
                        return _result_value(mem_addr, "base+ldr", instr, mem_addr=mem_addr, loaded=loaded)
            addr = _first_address_operand(instr)
            if addr is not None:
                loaded = _read_ptr(memory, addr)
                return _result_value(addr, "ldr_literal", instr, mem_addr=addr, loaded=loaded)
        if mnemonic in ("MOV", "MOVZ", "MOVK", "MOVN", "ORR"):
            scalar = _first_scalar_operand(instr)
            if scalar is not None:
                return _result_value(_s64(scalar), mnemonic.lower(), instr)
            src_reg = _first_register_operand(instr, 1)
            if src_reg:
                reg_name = src_reg
                instr = instr.getPrevious()
                steps += 1
                continue
        return {"value": None, "source": mnemonic.lower(), "instruction": instr.toString()}
    return {"value": None, "source": "unresolved", "scan_limit": max_back}


def _symbols_at_address(symtab, addr):
    names = []
    try:
        sym_iter = symtab.getSymbols(toAddr(_s64(addr)))
    except Exception:
        sym_iter = []
    for sym in sym_iter:
        name = sym.getName() or ""
        if name and name not in names:
            names.append(name)
    return names


def _record_match(matches, seen, instr, nxt, got_addr, got_block, kind, has_add, memory, symtab, branch, resolved=None):
    key = (
        instr.getAddress().getOffset(),
        nxt.getAddress().getOffset() if nxt else 0,
        got_addr,
        branch.getAddress().getOffset() if branch else 0,
        kind,
    )
    if key in seen:
        return
    seen.add(key)
    stub_addr = branch.getAddress().getOffset() if branch else instr.getAddress().getOffset()
    entry = {
        "stub_address": _format_addr(_s64(stub_addr)),
        "stub_symbol_names": _symbols_at_address(symtab, stub_addr),
        "stub_block": (memory.getBlock(instr.getAddress()).getName() if memory.getBlock(instr.getAddress()) else None),
        "kind": kind if kind else ("adrp_add_ldr" if has_add else "adrp_ldr"),
        "adrp": _format_addr(_s64(instr.getAddress().getOffset())),
        "ldr": _format_addr(_s64(nxt.getAddress().getOffset())) if nxt else None,
        "ldr_inst": str(nxt) if nxt else None,
        "got_address": _format_addr(_s64(got_addr)),
        "got_block": got_block.getName() if got_block else None,
    }
    if branch:
        entry["branch"] = _format_addr(_s64(branch.getAddress().getOffset()))
        entry["branch_inst"] = str(branch)
    loaded = None
    try:
        loaded = memory.getLong(toAddr(_s64(got_addr)))
    except Exception:
        loaded = None
    if loaded is not None:
        entry["loaded_value"] = _format_addr(_s64(loaded))
    if resolved:
        entry["resolve_source"] = resolved.get("source")
        entry["resolve_value"] = resolved.get("value")
        entry["resolve_instruction"] = resolved.get("instruction")
    matches.append(entry)


def _scan_stubs(addr_set, lookahead, got_blocks, memory, symtab, listing, matches, seen):
    adrp_seen = 0
    branch_seen = 0
    branch_hits = 0
    instr_iter = listing.getInstructions(addr_set, True)
    while instr_iter.hasNext() and not monitor.isCancelled():
        instr = instr_iter.next()
        if not isinstance(instr, Instruction):
            continue
        if _is_branch(instr):
            branch_seen += 1
            target_reg = _call_target_register(instr)
            if target_reg:
                resolved = _resolve_reg_value(instr.getPrevious(), target_reg, memory, max_back=lookahead, depth=2)
                mem_addr = resolved.get("_value_int") if resolved else None
                if mem_addr is not None:
                    blk = _addr_in_blocks(mem_addr, got_blocks)
                    if blk:
                        _record_match(
                            matches,
                            seen,
                            instr,
                            None,
                            mem_addr,
                            blk,
                            "branch_resolve",
                            False,
                            memory,
                            symtab,
                            instr,
                            resolved=resolved,
                        )
                        branch_hits += 1
            continue
        if not _is_arm64_adrp(instr):
            continue
        adrp_seen += 1
        pages = _adrp_pages(instr)
        if not pages:
            continue
        dest = _adrp_dest_reg(instr)
        if not dest:
            continue
        reg_bases = {dest: {page: False for page in pages}}
        branch = None
        nxt = instr
        for _ in range(lookahead):
            nxt = listing.getInstructionAfter(nxt.getAddress()) if nxt else None
            if nxt is None:
                break
            if _is_branch(nxt):
                branch = nxt
                continue
            add = _add_sub_imm(nxt)
            if add:
                dreg, sreg, imm, sign = add
                if sreg in reg_bases:
                    bases = reg_bases[sreg]
                    dest_bases = reg_bases.setdefault(dreg, {})
                    for base, has_add in bases.items():
                        new_base = _s64(base + sign * imm)
                        if new_base is None:
                            continue
                        dest_bases[new_base] = True or has_add
                continue
            if not _is_ldr(nxt):
                continue
            lit_addr = _ldr_literal_addr(nxt)
            if lit_addr is not None:
                blk = _addr_in_blocks(lit_addr, got_blocks)
                if blk:
                    _record_match(matches, seen, instr, nxt, lit_addr, blk, "ldr_literal", False, memory, symtab, branch)
                    break
            base_reg, offset = _ldr_base_offset(nxt)
            if not base_reg or base_reg not in reg_bases:
                continue
            offset = offset or 0
            for base, has_add in reg_bases[base_reg].items():
                candidate = _s64(base + offset)
                if candidate is None:
                    continue
                blk = _addr_in_blocks(candidate, got_blocks)
                if not blk:
                    continue
                _record_match(matches, seen, instr, nxt, candidate, blk, None, has_add, memory, symtab, branch)
                break
    return adrp_seen, branch_seen, branch_hits


def run():
    global _RUN_CALLED
    if _RUN_CALLED:
        return
    _RUN_CALLED = True
    out_dir = None
    try:
        args = getScriptArgs()
        if len(args) < 2:
            print("usage: kernel_stub_got_map.py <out_dir> <build_id> [block_substr] [lookahead] [exec_only] [all]")
            return
        out_dir = args[0]
        build_id = args[1] if len(args) > 1 else ""
        block_substr = args[2] if len(args) > 2 and args[2] else "stub"
        lookahead = _parse_int(args[3], 6) if len(args) > 3 else 6
        exec_only = True
        if len(args) > 4:
            exec_only = str(args[4]).strip() != "0"
        scan_all = False
        if len(args) > 5:
            scan_all = str(args[5]).strip().lower() == "all"

        _ensure_out_dir(out_dir)
        all_blocks, picked = _select_blocks(block_substr, exec_only, scan_all)
        addr_set = _block_set(picked)
        got_blocks, got_mode = _find_got_blocks()
        listing = currentProgram.getListing()
        memory = currentProgram.getMemory()
        symtab = currentProgram.getSymbolTable()
        matches = []
        seen = set()
        adrp_seen, branch_seen, branch_hits = _scan_stubs(
            addr_set, lookahead, got_blocks, memory, symtab, listing, matches, seen
        )
        meta = {
            "build_id": build_id,
            "program": currentProgram.getName(),
            "block_substr": block_substr,
            "lookahead": lookahead,
            "exec_only": exec_only,
            "scan_all_blocks": scan_all,
            "adrp_seen": adrp_seen,
            "branch_seen": branch_seen,
            "branch_hits": branch_hits,
            "match_count": len(matches),
            "got_block_mode": got_mode if got_blocks else None,
            "got_blocks": [
                {
                    "name": b.getName(),
                    "start": _format_addr(_s64(b.getStart().getOffset())),
                    "end": _format_addr(_s64(b.getEnd().getOffset())),
                }
                for b in got_blocks
            ],
            "block_filter": [
                {
                    "name": b.getName(),
                    "start": _format_addr(_s64(b.getStart().getOffset())),
                    "end": _format_addr(_s64(b.getEnd().getOffset())),
                }
                for b in picked
            ],
            "all_block_names": sorted(set((b.getName() or "") for b in all_blocks)),
        }
        with open(os.path.join(out_dir, "stub_got_map.json"), "w") as f:
            json.dump({"meta": meta, "stubs": matches}, f, indent=2, sort_keys=True)
        print("kernel_stub_got_map: %d matches (ADRPs seen: %d)" % (len(matches), adrp_seen))
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
